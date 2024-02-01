package net.newcapec.bsacs.register.impl;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import net.newcapec.bsacs.entity.CustomerMapping;
import net.newcapec.bsacs.entity.Dict;
import net.newcapec.bsacs.entity.SuZhuConfig;
import net.newcapec.bsacs.manager.CustomerMappingManager;
import net.newcapec.bsacs.manager.DictManager;
import net.newcapec.bsacs.manager.SuZhuConfigManager;
import net.newcapec.bsacs.register.BsacsRegister;
import net.newcapec.bsacs.register.BsacsServices;
import net.newcapec.bsacs.utils.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 农行快E通对接
 *
 * @author hanxq
 * @date 2019-06-03
 */
public class ABChinaNewBsacsService extends BsacsRegister implements BsacsServices {

    protected final transient Logger log = LoggerFactory.getLogger(this.getClass());

    private PreferenceUtils preferenceUtils;
    private DictManager dictManager;
    private CustomerMappingManager customerMappingManager;
    private SuZhuConfigManager suZhuConfigManager;

    @Override
    public String light(HttpServletRequest request, HttpServletResponse response) {
        Map<String, String> params = ToolsUtils.getParameterMap(request);
        JSONObject data = new JSONObject();
        for (Map.Entry<String, String> param : params.entrySet()) {
            String key = param.getKey();
            String value = param.getValue();
            data.put(key, value);
        }
        request.setAttribute("data", data.toJSONString());
        return "abchinanew";
    }

    @Override
    public String redirect(HttpServletRequest request, HttpServletResponse response, JSONObject suZhuJson, Date currentTime) throws IOException {
        JSONObject dataJson = ToolsUtils.getJSONData(request);
        JSONObject retjson = new JSONObject();
        // 判断参数
        String code = StringUtils.isNotBlank(dataJson.getString("code")) ? dataJson.getString("code") : dataJson.getString("amp;code");// 兼容农行ios环境
        String flag = suZhuJson.getString("flag");
        JSONObject abchinaJson = suZhuJson.getJSONObject("abchina");
        if (abchinaJson == null) {
            retjson.put("error", true);
            retjson.put("message", "农行快E通宿主配置出错");
            return retjson.toJSONString();
        }
        // 获取农行快E通用户openid
        JSONObject abchinaData = queryOpenidByCode(abchinaJson, flag, code, abchinaJson.getString("appid"), abchinaJson.getString("appkey"),
                abchinaJson.getString("redirecturi"), abchinaJson.getString("abchina_accesstoken_url"), abchinaJson.getString("abchina_userinfo_url"), request);

        if (abchinaData == null) {
            retjson.put("error", true);
            retjson.put("message", "请求农行快E通获取openid失败");
            return retjson.toJSONString();
        }

        String openid = abchinaData.getString("openID");
        String idNo = abchinaData.getString("idNo");
        if (StringUtils.isBlank(idNo) || StringUtils.isBlank(openid)) {
            retjson.put("error", true);
            retjson.put("message", "请求农行快E通返回数据为空");
            return retjson.toJSONString();
        }

        Dict dict = dictManager.getDict(flag);
        String customerCode = suZhuJson.getString("customerCode");
        if (StringUtils.isBlank(customerCode)) {
            String collegeNo = dataJson.getString("customer_code");
            CustomerMapping customerMapping = customerMappingManager.getCustomerMapping(SuZhuConfig.ABCHINA, collegeNo);
            if (customerMapping != null) {
                customerCode = customerMapping.getCustomerid();
            } else {
                retjson.put("error", true);
                retjson.put("message", "该校暂未开通");
                return retjson.toJSONString();
            }
        }
        // 先查
        String uid = MD5Utils.MD5(openid);
        accessLogManager.save("", System.currentTimeMillis(), System.currentTimeMillis(), flag,
                "openid值:" + openid, "md5加密后uid值:" + uid, request.getRemoteAddr(), request.getHeader("User-Agent"));
        String client_id = suZhuJson.getString("client_id");
        String client_secret = suZhuJson.getString("client_secret");
        String salt = suZhuJson.getString("salt");
        Boolean cookiesecur = false;
        Boolean secure = suZhuJson.getBoolean("cookiesecur");
        if (secure != null) {
            cookiesecur = secure;
        }
        String userSn = customerCode + "_" + uid + "_" + client_id;
        String userData = dataJson.toJSONString();
        Boolean group = suZhuJson.getBoolean("group");
        if (group == null) {
            group = false;
        }
        String qudao = flag + "_" + customerCode;
        if (group) {
            String groupflag = suZhuJson.getString("groupflag");
            qudao = groupflag + "_" + customerCode;
            userSn = userSn + "_" + groupflag;
        }
        Integer source = SuZhuConfig.SUZHU_SOURCE.get(SuZhuConfig.ABCHINA);
        if (dict != null) {
            source = dict.getCode();
        }
        boolean alwaysBindCard = abchinaJson.getBooleanValue("alwaysBindCard");
        // 查询是否有注册用户 若没有先注册
        retjson = registerAndBindCardNopwdByIdNo(source, idNo, null, uid, userData, userSn, customerCode, client_id, client_secret, salt, currentTime, qudao, group, flag  , alwaysBindCard);
        if (retjson.getBoolean("error")) {
            return retjson.toJSONString();
        }
        Boolean isBindEcard = retjson.getBoolean("bindEcard");
        String mobile = retjson.getString("mobile");
        String token = retjson.getString("token");

        String isForceBindCard = suZhuJson.getString("isForceBindCard"); // 是否强制绑卡
        Boolean forceBindCard = false;
        if (StringUtils.isNotBlank(isForceBindCard)) {
            forceBindCard = Boolean.parseBoolean(isForceBindCard);
        }
        dataJson.put("appId", client_id);
        dataJson.put("flag", flag);
        dataJson.put("token", token);
        dataJson.remove("code");
        JSONObject clientParam = new JSONObject();
        JSONObject customClientParam = ToolsUtils.processBlankData(suZhuJson.getJSONObject("clientParam"));
        clientParam.putAll(dataJson);
        clientParam.putAll(customClientParam);
        String redirect_url = ToolsUtils.getUrl(suZhuJson.getString("clientUrl"), clientParam);// TODO 跳转url带参数
        if (!isNewVersion(request.getHeader("User-Agent"), preferenceUtils.getAbchinaAndroidNormalVersion())) {
            redirect_url = URLEncoder.encode(redirect_url, "UTF-8");
        }
        String campusOpenUrl = suZhuJson.getString("campusOpenUrl");
        JSONObject paramJson = new JSONObject();// TODO 重新组装url所需要的参数
        paramJson.put("redirect_uri", redirect_url);
        paramJson.put("client_id", client_id);
        String domain = suZhuJson.getString("domain");

        paramJson.put("customerCode", customerCode);
        String hidden = suZhuJson.getString("hidden"); //是否显示logo等信息
        if (StringUtils.isNotBlank(hidden)) {
            paramJson.put("hidden", Boolean.parseBoolean(hidden));
        }
        String loginType = suZhuJson.getString("loginType");//是否自定义配置登录页
        String custom_login_page = suZhuJson.getString("custom_login_page");
        if (StringUtils.isNotBlank(loginType)) {
            paramJson.put("login_type", loginType);
            paramJson.put("custom_login_page", custom_login_page);
        } else {
            paramJson.put("login_type", "bindlogin");
        }
        String url = ToolsUtils.bindCardAndLogin(request, response, campusOpenUrl, forceBindCard, isBindEcard,
                domain, mobile, token, paramJson, cookiesecur);
        retjson.put("error", false);
        retjson.put("url", url);
        retjson.put("message", "请求完成");
        log.debug("农行快E通请求地址:" + url);

        return retjson.toJSONString();
    }


    /**
     * 根据code appId appsecret 获取用户的openId
     *
     * @return
     */
    private JSONObject queryOpenidByCode(JSONObject abchinaJson, String flag, String code, String appid, String appsecret, String redirectUri, String accesstokenUri, String userinfoUri, HttpServletRequest request) {
        Map<String, String> param = new HashMap<String, String>();
        param.put("grant_type", "authorization_code");
        param.put("client_id", appid);
        param.put("client_secret", appsecret);
        param.put("code", code);
        param.put("redirect_uri", redirectUri);

        String openid = null;
        String idNo = null;
        long startTime = System.currentTimeMillis();
        try {
            // 1.获取access_token         返回的json参数
            // access_token: AA******Pd5_u0ENeSjk5NBe7f87HcVb0SN_W9Z7GQ
            // token_type: bearer
            // expires_in: 120    单位(秒)
            // refresh_token: 3NEo!IAAAA******HZO6d3o
            // scope: name_phone
            String json = HttpRequestUtils.sendHttpRequestForm(accesstokenUri, param);
            accessLogManager.save("", startTime, System.currentTimeMillis(), flag,
                    "获取accessToken参数:" + param, "返回值:" + json, request.getRemoteAddr(), request.getHeader("User-Agent"));
            //log.info("请求农行快E通获取access_token:{}", json);
            JSONObject accessJson = JSONObject.parseObject(json);
            String access_token = accessJson.getString("access_token");
            // 2.获取open_id
            Map<String, String> headerPrm = new HashMap<String, String>();
            headerPrm.put("Authorization", "Bearer " + access_token);// todo 验证是否需要加前缀 Bearer
            String myCertPath = abchinaJson.getString("myCertPath");
            String myCertPwd = abchinaJson.getString("myCertPwd");
            String abcPubCertPath = abchinaJson.getString("abcPubCertPath");
            String userInfo = AbchinaGateWayUtils.post(myCertPath, myCertPwd, abcPubCertPath, appid, userinfoUri, "{}", "SHA256", true, appsecret, access_token);
            accessLogManager.save("", startTime, System.currentTimeMillis(), flag,
                    "获取用户信息请求数据:" + headerPrm, "返回值:" + userInfo, request.getRemoteAddr(), request.getHeader("User-Agent"));
            //log.info("请求农行快E通获取用户信息:{}", json);
            if (StringUtils.isNotBlank(userInfo)) {
                JSONObject userInfoJson = JSONObject.parseObject(userInfo);
                if ("0000".equals(userInfoJson.getString("RetCode"))) {// 成功
                    openid = userInfoJson.getString("OpenID");
                    idNo = userInfoJson.getString("IDNo");
                    JSONObject data = new JSONObject();
                    data.put("openID", openid);
                    data.put("idNo", idNo);
                    return data;
                }
            }
        } catch (Exception e) {
            log.error("请求农行快E通获取openid:" + e.getMessage());
            accessLogManager.save("", startTime, System.currentTimeMillis(), flag,
                    "农行接口请求", e.getMessage(), request.getRemoteAddr(), request.getHeader("User-Agent"));
            e.printStackTrace();
        }
        return null;
    }

    public PreferenceUtils getPreferenceUtils() {
        return preferenceUtils;
    }

    public void setPreferenceUtils(PreferenceUtils preferenceUtils) {
        this.preferenceUtils = preferenceUtils;
    }

    public DictManager getDictManager() {
        return dictManager;
    }

    public void setDictManager(DictManager dictManager) {
        this.dictManager = dictManager;
    }

    public CustomerMappingManager getCustomerMappingManager() {
        return customerMappingManager;
    }

    public void setCustomerMappingManager(CustomerMappingManager customerMappingManager) {
        this.customerMappingManager = customerMappingManager;
    }

    public SuZhuConfigManager getSuZhuConfigManager() {
        return suZhuConfigManager;
    }

    public void setSuZhuConfigManager(SuZhuConfigManager suZhuConfigManager) {
        this.suZhuConfigManager = suZhuConfigManager;
    }

    private boolean isNewVersion(String agent, String androidNormalVerion) {
        boolean flag = true;// 当前版本 >= 指定版本
        if (androidNormalVerion != null
                && agent != null
                && agent.indexOf("BankabcAndroid") >= 0) {
            String ag = agent.substring(agent.indexOf("BankabcAndroid"));
            String currVersion = ag.substring(ag.indexOf("/") + 1, ag.indexOf(" "));

            String[] nmVersionArr = androidNormalVerion.split("\\.");
            String[] currVersionArr = currVersion.split("\\.");
            int minlen = nmVersionArr.length < currVersionArr.length ? nmVersionArr.length : currVersionArr.length;
            for (int i = 0; i < minlen; i++) {
                int c = Integer.parseInt(currVersionArr[i]);
                int n = Integer.parseInt(nmVersionArr[i]);
                if (c == n) {
                    continue;
                } else if (c < n) {
                    flag = false;
                    break;
                } else {
                    break;
                }
            }
        }
        return flag;
    }
}
