package com.inori.bot.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class BotConfig {

    public static String APPID;

    public static String TOKEN;

    public static String APP_SECRET;

    @Value("${bot.appid}")
    public void setAPPID(String APPID) {
        BotConfig.APPID = APPID;
    }

    @Value("${bot.token}")
    public void setTOKEN(String TOKEN) {
        BotConfig.TOKEN = TOKEN;
    }

    @Value("${bot.secret}")
    public void setAppSecret(String APP_SECRET) {
        BotConfig.APP_SECRET = APP_SECRET;
    }

    // "api.sgroup.qq.com" "sandbox.api.sgroup.qq.com"
    public static final String SANDBOX_DOMAIN = "https://sandbox.api.sgroup.qq.com";

    public static final String DOMAIN = "https://api.sgroup.qq.com";

    // /v2/groups/{group_openid}/messages
    public static final String POST_GROUP_MESSAGE = "/v2/groups/%s/messages";

    // /channels/{channel_id}/messages
    public static final String POST_CHANNEL_MESSAGE = "/channels/%s/messages";

    // /v2/users/{openid}/messages
    public static final String POST_PRIVATE_MESSAGE = "/v2/users/%s/messages";

    // /v2/users/{openid}/files 发送私聊文件
    public static final String POST_PRIVATE_FILE = "/v2/users/%s/files";

    // /v2/groups/{group_openid}/files 发送私聊文件
    public static final String POST_GROUP_FILE = "/v2/groups/%s/files";
}
