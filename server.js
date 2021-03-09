const process = require("process");
const fs = require("fs");
const ini = require("ini");
const radius = require("radius");
const dgram = require("dgram");
const crypto = require('crypto');
const handlers = require("./handlers");

const authServer = dgram.createSocket("udp4");
const acctServer = dgram.createSocket("udp4");

/*
* Крик души или вольная реализация простого форматированного вывода
* */
function formatStr() {
    if(arguments.length) {
        let num = 0;
        let args = arguments;
        return arguments[0].replace(/%s/g, function(){ return args[++num]; });
    } return "";
}

/*
* Контроль наличия обязательных параметров в запросе клиента
* */
radius.vendorAttributesControl = (config, packet) => {
    /* Обязательные параметры, переданные клиентом */
    if (!!!packet.attributes["NAS-IP-Address"] || 
        !!!packet.attributes["NAS-Identifier"] ||
        !!!packet.attributes["Service-Type"] ||
        !!!packet.attributes["User-Name"]
    ) return false;
    /* Проверка значений параметров */
    if (!!!config.address    || config.address    !== packet.attributes["NAS-IP-Address"]) return false;
    if ( !!config.identifier && config.identifier !== packet.attributes["NAS-Identifier"]) return false;
    if (!packet.attributes["User-Name"].match("^[^/`]{3,16}$")) return false;
    return true;
}

/*
* Формирует список обработчиков для разбора запроса клиента
* Список составляется на основе параметров "protokol_<name> = yes" в конфиге сервера или клиента
* */
radius.vendorProtokolsControl = (config) => {
    let protokol = [];
    for (const param in config) {
        let match = param.match(/^protokol_(pap|chap|mschapv[12])$/);
        if (match && config[param] === 'yes') {
            switch (match[1]) {
                case "mschapv2": protokol.push(handlers.MSChapV2AuthHandler); break;
                case "mschapv1": protokol.push(handlers.MSChapV1AuthHandler); break;
                case "chap": protokol.push(handlers.ChapAuthHandler); break;
                case "pap":  protokol.push(handlers.PapAuthHandler);  break;
            }
        }
    }
    if (protokol.length) return protokol;
    return false
}

/*
* Небольшой класс, предназначенный для работы с выводом данных
* Основная задача - иметь возможность, в одноме месте, вносить изменения по обработке вывода, например, писать его в файл
* */
class logging {
    constructor(packet) {
        this.identifier = packet.identifier.toString().padStart(5, "0");
    }

    message() {
        let message = formatStr.apply(null, arguments);
        console.log("[CID %s] %s", this.identifier, message);
    }

    static global() {
        let message = formatStr.apply(null, arguments);
        console.log(message);
    }
};

/*
*
* */
let config = new class config {
    #cfg = {
        server: {
            "listener": "0.0.0.0",
            "authPort": 1812,
            "acctPort": 1813
        },
        client: {}
    }

    constructor(file) {
        let obj = this.read(file || "./config/server.ini");
        if (obj) this.update(this.#cfg, obj);
        else logging.global("Can't read the file %s", file);
    }

    /* Метод обвноляет эталонное дерево конфига в RAM на основание данных полученных из другой структуры, например, ini файла */
    update(tree, source) {
        for (const [section, cfg] of Object.entries(source)) {
            if (!!tree[section]) {
                for (const [name, value] of Object.entries(cfg)) {
                    tree[section][name] = value;
                }
            }
        }
        return tree;
    }

    /* Чтение ini файлов */
    read(file, exitOnError) {
        exitOnError = exitOnError || true;
        try {
            if (fs.existsSync(file)) {
                return ini.parse(fs.readFileSync(file, "utf-8"));
            }
        } catch(error) {
            logging.global("Can't read the file %s", file);
            if (exitOnError) process.exit();
        }
        return false;
    }

    /* Возвращает ветку дерева */
    get(section) {
        return (!!this.#cfg[section]) ? this.#cfg[section] : {};
    }

    client()  { return this.get("client"); }
    server()  { return this.get("server"); }
}();

/*
* Список обслуживаемых сервисов
* */
class radiusEvent {
    static login = "Login-User";
    static ppp = "Framed-User";
}

/*
* Контейнер для хранения профиля
* Используется для передачи данных профиля между объектами и дает возможность убедиться, что передан именно профиль, а не что-то другое
* */
class userProfile {
    #username = ""
    #password = ""
    #attributes = [];
    #attrExists = false;

    constructor(username, password) {
        this.#username = username;
        this.#password = password;
    }

    /* Добавление атрибутов, возвращаемых клиенту */
    addAttr(name, value) {
        let append = true;
        for (const [id, attr] of Object.entries(this.#attributes)) {
            if (attr[0] === name) {
                this.#attributes[id][1] = value;
                append = false;
            }
        }
        if (append) {
            this.#attributes.push([name, value]);
            this.#attrExists = true;
        }
    }

    /* Простая проверка валидности профиля */
    valid() {
        if (!!this.#username.length && !!this.#password.length) {
            if (this.#attrExists && !this.#attributes.length) return false;
            return true
        }
        return false;
    }

    /* Возвращает основной профиль или false */
    get() {
        if (this.valid()) {
            return {
                username: this.#username,
                password: this.#password,
                attributes: this.#attributes
            }
        }
        return false;
    }

    /* Возвращает тот параметр, на который и похож */
    username() { return this.#username || false; }
    password() { return this.#password || false; }
    attributes() { return this.#attributes || {} }
}

/*
* Класс описывающий обработку событий
* */
let mikrotik = new class mikrotik {
    #onevent = {

    };
    vendor = {
        id: 14988
    };

    constructor() {

    }

    /* Регистрация событий для обработчика */
    on(service, identifier, event) {
        let type = identifier.constructor.name;
        if (type.match("^(String|RegExp)$")) {
            if (!!!this.#onevent[service]) this.#onevent[service] = {
                String: {},
                RegExp: {}
            }
            if (!!!this.#onevent[service][type][identifier]) {
                switch (type) {
                    case 'String': this.#onevent[service][type][identifier] = event; break;
                    case 'RegExp': this.#onevent[service][type][identifier.toString()] = { regexp: identifier, event: event }; break;
                }
            } else {
                logging.global("The event for the identifier \"%s\" is already registered in the \"%s\" service", identifier, service);
            }
        } else {
            logging.global("Unknown service type");
        }
    }

    /* Обработчик профилей, не связанных со статическими файлами профилей */
    profileUserHandler(service, username, log) {
        if (!!!this.#onevent[service]) return false;
        let events = this.#onevent[service];
        for (const [stype, list] of Object.entries(events)) {
            if (!!events[stype]) {
                switch (stype) {
                    /* Статический профиль в оперативной памяти (описан в коде) */
                    case 'String':
                        if (!!events[stype][username]) {
                            switch (typeof events[stype][username]) {
                                case 'string':
                                    let profile = new userProfile(username, events[stype][username]);
                                    if (profile.valid()) {
                                        return profile
                                    }
                                case 'function':
                                    try {
                                        let profile = events[stype][username](service, username, log);
                                        if (profile instanceof userProfile && profile.valid()) {
                                            return profile;
                                        }
                                    } catch(error) {
                                        log.message("An error was detected in the user-defined function that handles the %s event for the user %s: %s", 
                                            service,
                                            username,
                                            error.message
                                        );
                                    }
                            }
                            return false;
                        }
                        break;
                    /* Профиль подпадающий под регулярное выражение */
                    case 'RegExp':
                        for (const [id, event] of Object.entries(list)) {
                            if (username.match(event.regexp)) {
                                switch (typeof event.event) {
                                    case 'string':
                                        let profile = new userProfile(username, event.event);
                                        if (profile.valid()) {
                                            return profile;
                                        }
                                    case 'function':
                                        try {
                                            let profile = event.event(service, username, log);
                                            if (profile instanceof userProfile && profile.valid()) {
                                                return profile;
                                            }
                                        } catch(error) {
                                            log.message("An error was detected in the user-defined function that handles the %s event for the user %s: %s", 
                                                service,
                                                username,
                                                error.message
                                            );
                                        }
                                }
                                return false;
                            }
                        }
                        break;
                }
            }
        }
        return false;
    }

    /* Обработчик, занимающийся поиском профиля */
    handler(packet, config) {
        let log = new logging(packet);
        let service = packet.attributes["Service-Type"];
        let username = packet.attributes["User-Name"];
        /* ... */
        let profile = false;
        let iniPath = this.serviceToCatalog(service);
        if (iniPath) {
            /* Поиск статического профиля в ini файлах */
            if ((profile = config.read(iniPath + username + ".ini", false)) !== false) {
                return this.profilePacker(username, profile, config, packet);
            /* Профили в оперативной памяти */
            } else if ((profile = this.profileUserHandler(service, username)) !== false) {
                return profile;
            /* Профили RegExp в ini файлах */
            } else {
                let regExpPath = iniPath + "regexp/";
                let regExpHostname = false;
                try {
                    for (const [num, obj] of Object.entries(fs.readdirSync(regExpPath))) {
                        if (fs.lstatSync(regExpPath + obj).isFile()) {
                            if ((profile = config.read(regExpPath + obj, false)) !== false) {
                                if (!!profile.security.regexp) {
                                    try {
                                        regExpHostname = username.match(profile.security.regexp);
                                    } catch (error) {
                                        log.message("Error in custom regex in file %s: %s", regExpPath + obj, error.message);
                                    }
                                    if (regExpHostname) {
                                        if (!!!profile.security.password && !!profile.security.passwordTemplate) {
                                            profile.security.password = profile.security.passwordTemplate.replace(/\${[a-z0-9]+}/g, (tParam) => {
                                                let match = tParam.match(/([^\${}]+)/i);
                                                if (match) {
                                                    switch (match[0]) {
                                                        case 'hostname': return username;
                                                        case 'salt': return profile.security.salt;
                                                    }
                                                }
                                                return "";
                                            });
                                        }
                                    }
                                }
                                profile = this.profilePacker(username, profile, config, packet)
                                return profile;
                            }
                        }
                    }
                } catch (error) {
                    log.message("Error while parsing the regex section for config files: %s", error.message);
                }

                return false;
            }
        } else {
            log.message("The service \"%s\" is not associated with any directory", service);
        }

        return false;
    }

    /* Возвращает каталог сервиса или false */
    serviceToCatalog(service) {
        let template = "%s/config/%s/";
        switch (service) {
            case radiusEvent.login: return formatStr(template, __dirname, "users");
            case radiusEvent.ppp:   return formatStr(template, __dirname, "ppp");
        }
        return false;
    }

    /* Паковщик профиля пользователя. Обновляет дерево профиля, вычисляет хэш и контролирует динамические параметры */
    profilePacker(username, profile, config, packet) {
        let tree = {
            security: {
                regexp: "",
                username: username,
                passwordTemplate: "",
                password: "",
                salt: "",
                hash: ""
            },
            attributes: {
                group: {}
            }
        };
        config.update(tree, profile);
        if (!!tree.security.password) {
            this.passwordHashing(tree);
            let user = new userProfile(tree.security.username, tree.security.password);
            /* Секция атрибутов, передаваемых клиенту */
            for (const [attr, value] of Object.entries(tree.attributes)) {
                if ("string" === typeof value && !!value) {
                    user.addAttr(attr, value);
                }
            }
            /* Динамические атрибуты, значение выставляется в зависимости от совпадения с ip адресом клиента */
            for (const [attr, list] of Object.entries(tree.attributes.group)) {
                for (const [client, value] of Object.entries(tree.attributes.group[attr])) {
                    if (client === packet.attributes["NAS-IP-Address"]) {
                        if ("string" === typeof value && !!value) {
                            user.addAttr(attr, value);
                            break;
                        }
                    }
                }
            }   
            if (user.valid()) return user;
        }
        return false;
    }

    /* Вычисляет хэш в зависимости от выбранного алгоритма */
    passwordHashing(tree) {
        switch (tree.security.hash) {
            case "md5": 
            case "sha1":
            case "sha256":
            case "sha384":
            case "sha512":
                tree.security.password = crypto.createHash(tree.security.hash)
                    .update(tree.security.username + tree.security.salt)
                    .digest('hex')
                    .toString();
                break;
        }
    }

    /* Одна из возможностей подсмотреть ветку зарегистрированных событий */
    events() {
        console.log(this.#onevent);
    }
}();

function auth_listening() {
    let tcpClient = authServer.address();
    logging.global("Radius authenticating server listening %s:%s", tcpClient.address, tcpClient.port);
}

function acct_listening() {
    let tcpClient = authServer.address();
    logging.global("Radius accounting server listening %s:%s", tcpClient.address, tcpClient.port);
}

function acct_message(msg, rinfo) {
    let packet = radius.decode_without_secret({packet: msg});
    //logging.global("acct: %s", packet.code, packet.attributes);
}

function auth_message(msg, req) {
    let response = false;
    let packet = radius.decode_without_secret({packet: msg});
    let log = new logging(packet);

    log.message("Access-Request from \"%s\", incoming tcp connections %s:%s",
        packet.attributes["NAS-Identifier"],
        req.address,
        req.port
    );
    log.message("Client \"%s:%s\", service \"%s\"",
        packet.attributes["User-Name"],
        packet.attributes["Calling-Station-Id"],
        packet.attributes["Service-Type"]
    );

    /* Пока работаем только с запросами на авторизацию маршрутизаторов */
    if (packet.code != "Access-Request") {
        log.message("Unknown packet type: %s", packet.code);
        return;
    }

    /* Пытаемся найти клиента среди объявленных в server.ini, секция [client.<virtual name>] */
    for (const [virtualName, cfg] of Object.entries(config.client())) {
        if (response) break;
        /* Проверяем обязательные параметры, передаваемые клиентом, а также ищем совпадление профиля слиента */
        if (radius.vendorAttributesControl(cfg, packet)) {
            let packet = radius.decode({packet: msg, secret: cfg.secret});
            /* Составляем список протоколов для проверки авторизации (pap, chap, mschapv1, mschapv2), если нет списка в конфиге клиента, берем из конфига сервера */
            let protokol = radius.vendorProtokolsControl(cfg) || radius.vendorProtokolsControl(config.server());
            if (protokol.length) {
                /* Ищем профиль маршрутизатора MikroTik, ожидаем получить объект userProfile или false */
                const profile = mikrotik.handler(packet, config);
                //if (profile) console.log(profile.get());
                if (profile instanceof userProfile) {
                    /* Подбираем протокол из списка, полученного ранее в конфиге */
                    protokol.some(handlerClass => {
                        if (!response) {
                            var handler = new handlerClass(packet, cfg.secret, profile.username(), profile.password());
                            if (handler.authable()) {
                                log.message("The radius client profile found, virtual name: %s", virtualName);
                                log.message("The radius client using protokol: %s", handler.constructor.name);
                                let args = handler.check();
                                /* Проверяем, что ключи совпали, пользователю разрешен доступ */
                                if (args.code == "Access-Accept") {
                                    if (profile.attributes().length) {
                                        let vendorSpecific = [];
                                        /* Составление списка дополнительных параметров, возвращаемых клиенту */
                                        for (const [attr, value] of profile.attributes()) {
                                            if (!!radius.attr_name_to_id(attr, -1)) {
                                                args.attributes.push([attr, value]);
                                            } else if (!!radius.attr_name_to_id(attr, 14988)) {
                                                vendorSpecific.push([attr, value]);
                                            } else {
                                                log.message("Attribute %s will not be sent because it does not fit the specification", attr);
                                            }
                                        }
                                        if (vendorSpecific.length) {
                                            args.attributes.push(["Vendor-Specific", 14988, vendorSpecific]);
                                        }
                                    }
                                    log.message("Access accept: %s", packet.attributes["User-Name"]);
                                } else {
                                    log.message("Access denied: %s", packet.attributes["User-Name"]);
                                }
                                response = radius.encode_response(args);
                            } else {
                                log.message("Inappropriate protokol: %s", handler.constructor.name);
                            }
                            /* Отвечаем клиенту, если мы готовы что-то передать */
                            if (response || "handlerClass" === typeof handler) {
                                response = response || radius.encode_response(handler.failed("access denied"));
                                authServer.send(response, 0, response.length, req.port, req.address, (error) => {
                                    if (error) {
                                        log.message("Error sending response to %s:%s",
                                            req.address,
                                            req.port
                                        );
                                    }
                                });
                            }
                        }
                    });

                }
            } else {
                log.message("The list of protocols used to check authorization is empty");
                break;
            }
            //return;
        }
    }

    if (!response) {
        log.message("Access denied: %s", packet.attributes["User-Name"]);
    }
}

/* Подключение словаря MikroTik */
radius.add_dictionary('./config/dictionary/mikrotik');

/* Регистрация событий Radius */
authServer.on("listening", auth_listening);
acctServer.on("listening", acct_listening);
authServer.on("message", auth_message);
acctServer.on("message", acct_message);

/* Debug */
//mikrotik.on(radiusEvent.login, new RegExp(`qwe1`, "i"), "qwe3");
//mikrotik.on(radiusEvent.login, new RegExp(`qwe2`, "i"), (service, username, log) => { 
//    return new userProfile(username, "qwerty"); 
//});
//mikrotik.on(radiusEvent.login, "test3", "qwe2");
//mikrotik.events();

/* Регистрация сервисов Radius */
authServer.bind(
    config.server().authPort,
    config.server().listener
);
acctServer.bind(
    config.server().acctPort,
    config.server().listener
);