const MOBILE_BROWSERS_IMPORT = require("./mobile_browsers.js");
const DESKTOP_BROWSERS_IMPORT = require("./desktop_browsers.js");
const OTHER_BROWSERS_IMPORT = require("./other_browsers.js");
const DESKTOP_OS_IMPORT = require("./desktop_os.js");
const MOBILE_OS_IMPORT = require("./mobile_os.js");
const COUNTRY_IMPORT = require("./country.js");
const MODEL_IMPORT = require("./model.js");
const ACTIVE_VPN_IMPORT = require("./active_vpn.js");

function indicators(data) {
  return new Promise((resolve) => {
    const INDICATORS = {
      isValid: false,
      isDisposable: false,
      // smtp_score: false,
      // overall_score: false,
      isGeneric: false,
      isCommon: false,
      isDns_valid: false,
      isHoneypot: false,
      deliverability_high: false,
      deliverability_medium: false,
      deliverability_low: false,
      isFrequent_complainer: false,
      spam_trap_score_high: false,
      spam_trap_score_medium: false,
      spam_trap_score_low: false,
      user_activity_high: false,
      user_activity_medium: false,
      user_activity_low: false,
      domain_velocity_high: false,
      domain_velocity_medium: false,
      domain_velocity_low: false,
      isCatch_all: false,
      didTimed_out: false,
      isSuspect: false,
      isRecent_abuse: false,
      //Common
      isLeaked: false,
      is90: false,
      is80: false,
      isBot: false,
      //Proxy|Fingerprint
      isVPN: false,
      isActiveVPN: false,
      isProxy: false,
      isTor: false,
      isActiveTor: false,
      isHighAbuseVelocity: false,
      isMediumAbuseVelocity: false,
      isLowAbuseVelocity: false,
      // mobile tracker
      isQemu: false,
      isRooted: false,
      isEmulationDetected: false,
      is_mobile_2g: false,
      is_mobile_3g: false,
      is_mobile_4g: false,
      is_mobile_data: false,
      is_no_internet: false,
      is_unknown: false,
      is_wifi: false,
      is_wireless: false,
      //phone
      isActive: false,
      isRisky: false,
      isLineActive: false,
      isDNC: false,
      // url
      is_unsafe: false,
      is_dns_valid: false,
      is_dns_invalid: false,
      is_suspicious: false,
      is_phishing: false,
      is_malware: false,
      is_parked: false,
      is_spam: false,
      is_adult: false,
      is_redirected: false,
      // calculated
      isUnknownBrowser: false,
      isDesktopBrowser: false,
      isMobileBrowser: false,
      isOtherBrowser: false,
      isUnknownOS: false,
      isMobileOS: false,
      isDesktopOS: false,
      isUnknownCountry: false,
      isUnknownFraudReason: false,
      isUnknownModel: false,
      isUnknownActiveVPN: false,
      isResiential: false,
      isDataCenter: false,
      isMobile: false,
      isEducation: false,
      isCorporate: false,

      country: false,
      os: false,
      browser: false,
      isVoip: false,
      model: false,
      // catch all
    };

    // ##########################################
    // Set indicators
    // ##########################################
    const MOBILE_BROWSERS = MOBILE_BROWSERS_IMPORT.Array;
    const DESKTOP_BROWSERS = DESKTOP_BROWSERS_IMPORT.Array;
    const OTHER_BROWSERS = OTHER_BROWSERS_IMPORT.Array;
    const DESKTOP_OS = DESKTOP_OS_IMPORT.Array;
    const MOBILE_OS = MOBILE_OS_IMPORT.Array;
    const COUNTRIES = COUNTRY_IMPORT.Array;
    const MODEL = MODEL_IMPORT.Array;
    const ACTIVE_VPN = ACTIVE_VPN_IMPORT.Array;

    // url
    if (data.unsafe && data.unsafe === true) {
      INDICATORS.is_unsafe = data.unsafe;
    }

    if (data.dns_valid && data.dns_valid === true) {
      INDICATORS.is_dns_valid = data.dns_valid;
    }

    if (data.dns_valid && data.dns_valid === false) {
      INDICATORS.is_dns_invalid = data.dns_valid;
    }

    if (data.suspicious && data.suspicious === true) {
      INDICATORS.is_suspicious = data.suspicious;
    }

    if (data.phishing && data.phishing === true) {
      INDICATORS.is_phishing = data.phishing;
    }

    if (data.malware && data.malware === true) {
      INDICATORS.is_malware = data.malware;
    }

    if (data.parking && data.parking === true) {
      INDICATORS.is_parked = data.parking;
    }

    if (data.spamming && data.spamming === true) {
      INDICATORS.is_spam = data.spamming;
    }

    if (data.adult && data.adult === true) {
      INDICATORS.is_adult = data.adult;
    }

    if (data.redirected && data.redirected === true) {
      INDICATORS.is_redirected = data.redirected;
    }

    // phone
    if (data.active && data.active === true) {
      INDICATORS.isActive = data.active;
    }
    if (data.do_not_call) {
      INDICATORS.isDNC = data.do_not_call;
    }
    if (data.phone_status === "Active Line") {
      INDICATORS.isLineActive = true;
    }
    if (data.voip) {
      INDICATORS.isVoip = data.voip;
    }
    if (data.risky) {
      INDICATORS.isRisky = data.risky;
    }
    if (data.qemu_detected) {
      INDICATORS.isQemu = data.qemu_detected;
    }
    if (data.rooted) {
      INDICATORS.isRooted = data.rooted;
    }
    if (data.emulation_detected) {
      INDICATORS.isEmulationDetected = data.emulation_detected;
    }

    if (data.valid) {
      INDICATORS.isValid = data.valid;
    }
    if (data.disposable) {
      INDICATORS.isDisposable = data.disposable;
    }

    // email

    // if (data.smtp_score) {
    //   smtp_score = data.smtp_score;
    // }
    // if (data.overall_score) {
    //   overall_score =
    //     data.overall_score;
    // }

    if (data.generic) {
      INDICATORS.isGeneric = data.generic;
    }

    if (data.common_domain) {
      INDICATORS.isCommon = data.common_domain;
    }

    if (data.dns_valid) {
      INDICATORS.isDns_valid = data.dns_valid;
    }

    if (data.honeypot) {
      INDICATORS.isHoneypot = data.honeypot;
    }

    if (data.deliverability && data.deliverability === "high") {
      INDICATORS.deliverability_high = true;
    }

    if (data.deliverability && data.deliverability === "medium") {
      INDICATORS.deliverability_medium = true;
    }

    if (data.deliverability && data.deliverability === "low") {
      INDICATORS.deliverability_low = true;
    }

    if (data.user_activity && data.user_activity === "high") {
      INDICATORS.user_activity_high = true;
    }

    if (data.user_activity && data.user_activity === "medium") {
      INDICATORS.user_activity_medium = true;
    }

    if (data.user_activity && data.user_activity === "low") {
      INDICATORS.user_activity_low = true;
    }

    if (data.domain_velocity && data.domain_velocity === "low") {
      INDICATORS.domain_velocity_low = true;
    }

    if (data.domain_velocity && data.domain_velocity === "medium") {
      INDICATORS.domain_velocity_medium = true;
    }

    if (data.domain_velocity && data.domain_velocity === "high") {
      INDICATORS.domain_velocity_high = true;
    }

    if (data.frequent_complainer) {
      INDICATORS.isFrequent_complainer = data.frequent_complainer;
    }

    if (data.spam_trap_score && data.spam_trap_score === "high") {
      INDICATORS.spam_trap_score_high = true;
    }

    if (data.spam_trap_score && data.spam_trap_score === "medium") {
      INDICATORS.spam_trap_score_medium = true;
    }

    if (data.spam_trap_score && data.spam_trap_score === "low") {
      INDICATORS.spam_trap_score_low = true;
    }

    if (data.catch_all) {
      INDICATORS.isCatch_all = data.catch_all;
    }

    if (data.timed_out) {
      INDICATORS.didTimed_out = data.timed_out;
    }

    if (data.suspect) {
      INDICATORS.isSuspect = data.suspect;
    }

    if (data.recent_abuse) {
      INDICATORS.isRecent_abuse = data.recent_abuse;
    }

    if (data.leaked) {
      INDICATORS.isLeaked = data.leaked;
    }

    if (data.abuse_velocity && data.abuse_velocity === "high") {
      INDICATORS.isHighAbuseVelocity = true;
    }

    if (data.abuse_velocity && data.abuse_velocity === "medium") {
      INDICATORS.isMediumAbuseVelocity = true;
    }

    if (data.abuse_velocity && data.abuse_velocity === "low") {
      INDICATORS.isLowAbuseVelocity = true;
    }

    // fraud score

    if (parseInt(data.fraud_chance) >= 90) {
      INDICATORS.is90 = true;
    }

    if (parseInt(data.fraud_score) >= 90) INDICATORS.is90 = true;

    if (parseInt(data.risk_score) >= 90) INDICATORS.is90 = true;

    if (parseInt(data.ip_fraud_score) >= 90) INDICATORS.is90 = true;

    if (parseInt(data.fraud_chance) < 90 && parseInt(data.fraud_chance) >= 80)
      INDICATORS.is80 = true;

    if (parseInt(data.fraud_score) < 90 && parseInt(data.fraud_score) >= 80)
      INDICATORS.is80 = true;

    if (parseInt(data.risk_score) < 90 && parseInt(data.risk_score) >= 80)
      INDICATORS.is80 = true;

    if (
      parseInt(data.ip_fraud_score) < 90 &&
      parseInt(data.ip_fraud_score) >= 80
    )
      INDICATORS.is80 = true;

    // IP / device tracker / mobile tracker
    if (data.bot_status) {
      INDICATORS.isBot = true;
    }
    if (data.vpn) {
      INDICATORS.isVPN = true;
    }
    if (data.active_vpn) {
      INDICATORS.isActiveVPN = true;
    }

    if (data.proxy) {
      INDICATORS.isProxy = true;
    }
    if (data.tor) {
      INDICATORS.isTor = true;
    }
    if (data.active_tor) {
      INDICATORS.isActiveTor = true;
    }

    //country
    if (data.country !== undefined) {
      if (
        data.country &&
        data.country !== undefined &&
        data.country !== "N/A"
      ) {
        if (!COUNTRIES.includes(data.country)) {
          INDICATORS.isUnknownCountry = true;
        }
      }
      if (data.country === "N/A") {
        INDICATORS.isUnknownCountry = true;
      }
    } else if (data.country_code !== undefined) {
      if (
        data.country_code &&
        data.country_code !== undefined &&
        data.country_code !== "N/A"
      ) {
        if (!COUNTRIES.includes(data.country_code)) {
          INDICATORS.isUnknownCountry = true;
        }
      }
      if (data.country_code === "N/A") {
        INDICATORS.isUnknownCountry = true;
      }
    }

    // unknown active_vpn

    if (data.active_vpn) {
      if (!ACTIVE_VPN.includes(data.active_vpn)) {
        INDICATORS.isUnknownActiveVPN = true;
      }
    }

    // model
    if (
      data.model &&
      data.model !== "N/A" &&
      data.cpu_model &&
      data.cpu_model !== "N/A" &&
      data.brand &&
      data.brand !== "N/A"
    ) {
      const KNOWN_MODEL_FOUND = MODEL.filter((item) => {
        if (
          item.model === data.model &&
          item.cpu === data.cpu_model &&
          item.brand === data.brand
        ) {
          return item.model;
        }
      });
      if (KNOWN_MODEL_FOUND.length <= 0) {
        INDICATORS.isUnknownModel = true;
      } else {
        INDICATORS.model = KNOWN_MODEL_FOUND;
      }
    }
    //OS
    if (data.operating_system && data.operating_system !== "N/A") {
      INDICATORS.operating_system = data.operating_system;
      if (
        !DESKTOP_OS.includes(data.operating_system) &&
        !MOBILE_OS.includes(data.operating_system)
      ) {
        INDICATORS.isUnknownOS = true;
      }
      if (DESKTOP_OS.includes(data.operating_system))
        INDICATORS.isDesktopOS = true;
      if (MOBILE_OS.includes(data.operating_system))
        INDICATORS.isMobileOS = true;
    }

    //browsers
    if (data.browser && data.browser !== "N/A") {
      INDICATORS.browser = data.browser;
      if (
        !DESKTOP_BROWSERS.includes(data.browser) &&
        !MOBILE_BROWSERS.includes(data.browser) &&
        !OTHER_BROWSERS.includes(data.browser) &&
        data.browser !== "N/A"
      ) {
        INDICATORS.isUnknownBrowser = true;
      }
      if (DESKTOP_BROWSERS.includes(data.browser))
        INDICATORS.isDesktopBrowser = true;
      if (MOBILE_BROWSERS.includes(data.browser))
        INDICATORS.isMobileBrowser = true;
      if (OTHER_BROWSERS.includes(data.browser))
        INDICATORS.isOtherBrowser = true;
    }

    //IP Types
    if (data.connection_type === "Residential") INDICATORS.isResiential = true;
    if (data.connection_type === "Data Center") INDICATORS.isDataCenter = true;
    if (data.connection_type === "Mobile") INDICATORS.isMobile = true;
    if (data.connection_type === "Education") INDICATORS.isEducation = true;
    if (data.connection_type === "Corporate") INDICATORS.isCorporate = true;

    //Device Connection Types
    if (data.device_connection_type === "2G") INDICATORS.is_mobile_2g = true;
    if (data.device_connection_type === "3G") INDICATORS.is_mobile_3g = true;
    if (data.device_connection_type === "4G") INDICATORS.is_mobile_4g = true;
    if (data.device_connection_type === "Mobile Data")
      INDICATORS.is_mobile_data = true;
    if (data.device_connection_type === "NO INTERNET")
      INDICATORS.is_no_internet = true;
    if (data.device_connection_type === "UNKNOWN") INDICATORS.is_unknown = true;
    if (data.device_connection_type === "WIFI") INDICATORS.is_wifi = true;
    if (data.device_connection_type === "Wireless")
      INDICATORS.is_wireless = true;

    if (data.country !== undefined) {
      INDICATORS.country = data.country;
    } else if (data.country_code !== undefined) {
      INDICATORS.country = data.country_code;
    }
    if (data.operating_system && data.operating_system !== "N/A")
      INDICATORS.OS = data.operating_system;

    resolve(INDICATORS);
  });
}

module.exports = { indicators };
