#include "config.h"

#include "file.h"

static void downloadDirCallback(struct xdccGetConfig *config, sds value);
static void parseLogLevel(struct xdccGetConfig *config, sds value);
static void allowAllCertsCallback(struct xdccGetConfig *config, sds value);

typedef void (*ConfigLineParserFunction) (struct xdccGetConfig *config, sds value);

struct ConfigLineParser {
    char *type;
    ConfigLineParserFunction parse_line;
};

static struct ConfigLineParser configLineCallbacks[] = {
    {"downloadDir",     downloadDirCallback},
    {"logLevel",        parseLogLevel},
    {"allowAllCerts",   allowAllCertsCallback},
};

static void allowAllCertsCallback(struct xdccGetConfig *config, sds value) {
     if (str_equals(value, "true")) {
        cfg_set_bit(config, ALLOW_ALL_CERTS_FLAG);
     }
     else {
        cfg_clear_bit(config, ALLOW_ALL_CERTS_FLAG);
     }
}

static void downloadDirCallback(struct xdccGetConfig *config, sds value) {
    sdsfree(config->targetDir);
    config->targetDir = sdsdup(value);
}

static void parseLogLevel(struct xdccGetConfig *config, sds logLevel) {
    if (str_equals(logLevel, "information")) {
        config->logLevel = LOG_INFO;
    }
    else if (str_equals(logLevel, "warn")) {
        config->logLevel = LOG_WARN;
    }
    else if (str_equals(logLevel, "error")) {
        config->logLevel = LOG_ERR;
    }
    else if (str_equals(logLevel, "quiet")) {
        config->logLevel = LOG_QUIET;
    }
}

static sds getDefaultConfigContent() {
    sds downloadDir = sdscatprintf(sdsempty(), "%s%s%s", getHomeDir(), getPathSeperator(), "Downloads");

    sds defaultConfigContent = sdscatprintf(sdsempty(), "downloadDir=%s\n", downloadDir);
    defaultConfigContent = sdscatprintf(defaultConfigContent, "logLevel=information\n");
    defaultConfigContent = sdscatprintf(defaultConfigContent, "allowAllCerts=true\n");

    sdsfree(downloadDir);

    return defaultConfigContent;
}

static void writeDefaultConfigFile() {
    sds configDir = getConfigDirectory();
    sds configPath = sdscatprintf(sdsempty(), "%s%s", configDir, "config");

    sds defaultConfigContent = getDefaultConfigContent();

    file_io_t *configFile = Open(configPath, "w");
    Write(configFile, defaultConfigContent, sdslen(defaultConfigContent));
    Close(configFile);

    sdsfree(defaultConfigContent);

    sdsfree(configPath);
    sdsfree(configDir);
}

static void createDefaultConfigFile() {
    sds configDir = getConfigDirectory();
    if (!dir_exists(configDir)) {
        if (mkdir(configDir, 0755) == -1) {
            DBG_WARN("cant create dir %s", configDir);
            perror("mkdir");
        }
    }

    writeDefaultConfigFile();
    sdsfree(configDir);
}

static void parseConfigLine(struct xdccGetConfig *config, sds line) {
    int count, i;
    size_t j = 0;
    char *seperator = "=";
    sds *splitted = sdssplitlen(line, sdslen(line), seperator, strlen(seperator), &count);

    if (count != 2) {
        return;
    }

    for (i = 0; i < count; i++)
        sdstrim(splitted[i], " \t");

    sds type = splitted[0], value = splitted[1];
    DBG_OK("%s=%s", type, value);

    size_t numCallbacks = sizeof (configLineCallbacks) / sizeof (struct ConfigLineParser);

    for (; j < numCallbacks; j++) {
        struct ConfigLineParser *lineParser = &configLineCallbacks[j];
        if (str_equals(type, lineParser->type)) {
            lineParser->parse_line(config, value);
        }
    }

    sdsfreesplitres(splitted, count);
}

static inline bool ignoreLine(sds line) {
    return strcmp(line, "") == 0 || line[0] == '#';
}

static void parseConfigString(struct xdccGetConfig *config, sds content) {
    int count, i;
    char *seperator = "\n";
    sds *splitted = sdssplitlen(content, sdslen(content), seperator, strlen(seperator), &count);

    for (i = 0; i < count; i++) {
        sdstrim(splitted[i], " \r\t");
        if (ignoreLine(splitted[i])) {
            continue;
        }

        parseConfigLine(config, splitted[i]);
    }

    sdsfreesplitres(splitted, count);
}

void parseConfigFile(struct xdccGetConfig *config) {
    DBG_OK("in parseConfigFile");
    sds configDir = getConfigDirectory();
    sds configFilePath = sdscatprintf(sdsempty(), "%s%s", configDir, "config");

    if (!file_exists(configFilePath)) {
        DBG_OK("config file does not exist, need to create one!");
        createDefaultConfigFile();
    }

    sds content = readTextFile(configFilePath);
    parseConfigString(config, content);

    sdsfree(content);
    sdsfree(configDir);
    sdsfree(configFilePath);
}
