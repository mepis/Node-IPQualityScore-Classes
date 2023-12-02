const MOBILE_BROWSERS_IMPORT = require("./mobile_browsers.js");
const DESKTOP_BROWSERS_IMPORT = require("./desktop_browsers.js");
const OTHER_BROWSERS_IMPORT = require("./other_browsers.js");
const DESKTOP_OS_IMPORT = require("./desktop_os.js");
const MOBILE_OS_IMPORT = require("./mobile_os.js");
const COUNTRY_IMPORT = require("./country.js");
const FRAUD_IMPORT = require("./fraud_reasons.js");
const MODEL_IMPORT = require("./model.js");

// ##########################################
// Define Metric Strings
// ##########################################
/* eslint-disable */

function assemble_ip_reports_array() {
  return new Promise(async (resolve) => {
    const DESKTOP_BROWSERS = DESKTOP_BROWSERS_IMPORT.Array;
    const MOBILE_BROWSERS = MOBILE_BROWSERS_IMPORT.Array;
    const OTHER_BROWSERS = OTHER_BROWSERS_IMPORT.Array;
    const DESKTOP_OS = DESKTOP_OS_IMPORT.Array;
    const MOBILE_OS = MOBILE_OS_IMPORT.Array;
    const COUNTRIES = COUNTRY_IMPORT.Array;
    const FRAUD_REASONS = FRAUD_IMPORT.Array;
    const MODELS = MODEL_IMPORT.Array;

    const DESKTOP_BROWSER_ARRAY = await create_browser_array(DESKTOP_BROWSERS);
    const MOBILE_BROWSER_ARRAY = await create_browser_array(MOBILE_BROWSERS);
    const OTHER_BROWSER_ARRAY = await create_browser_array(OTHER_BROWSERS);

    const DESKTOP_OS_ARRAY = await create_os_array(DESKTOP_OS);
    const MOBILE_OS_ARRAY = await create_os_array(MOBILE_OS);

    const COUNTRY_ARRAY = await create_country_array(COUNTRIES);

    const FRAUD_ARRAY = await create_fraud_array(FRAUD_REASONS);

    const MODEL_ARRAY = await create_model_array(MODELS);

    const RESPONSE = {
      ip_reports: {
        raw_data: [],
        label: "",
        IP: await get_indicators_object(),
        CONNECTION_TYPE: await get_connections_object(),
        DEVICE_CONNECTION_TYPE: await get_device_connections_object(),
        unknown_browsers: [],
        unknown_os: [],
        unknown_countries: [],
        unknown_brand: [],
        unknown_model: [],
        unknown_active_vpns: [],
        users_with_unknown_devices: [],
        unknown_fraud_reasons: [],
        DESKTOP_BROWSER_ARRAY,
        MOBILE_BROWSER_ARRAY,
        OTHER_BROWSER_ARRAY,
        DESKTOP_OS_ARRAY,
        MOBILE_OS_ARRAY,
        COUNTRY_ARRAY,
        FRAUD_ARRAY,
        MODEL_ARRAY,
      },
    };
    resolve(RESPONSE);
  });
}

function get_indicators_object() {
  return new Promise(async (resolve) => {
    resolve({
      // shared
      totals: {
        key: "Total",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      valid: {
        key: "Valid",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      recent_abuse: {
        key: "Recent Abuse",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      user_activity_high: {
        key: "User Activity: High",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      user_activity_medium: {
        key: "User Activity: Medium",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      user_activity_low: {
        key: "User Activity: Low",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // ip/dt: singles
      bot: {
        key: "Bot",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      proxy: {
        key: "Proxy",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      vpn: {
        key: "VPN",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      active_vpn: {
        key: "Active VPN",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      tor: {
        key: "TOR",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      active_tor: {
        key: "Active Tor",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      leaked: {
        key: "Leaked",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      abuse_velocity_high: {
        key: "Abuse Velocity: High",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      abuse_velocity_medium: {
        key: "Abuse Velocity: Medium",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      abuse_velocity_low: {
        key: "Abuse Velocity: Low",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // ip/dt: doubles
      bot_vpn: {
        key: "Bot & VPN",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      bot_proxy: {
        key: "Bot & Proxy",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      bot_tor: {
        key: "Bot & TOR",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      vpn_proxy: {
        key: "VPN & Proxy",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      vpn_tor: {
        key: "VPN & TOR",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // ip/dt: triples
      bot_vpn_proxy: {
        key: "BOT, VPN, & Proxy",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      bot_proxy_tor: {
        key: "BOT, Proxy, & TOR",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // mobile tracker
      qemu_detected: {
        key: "Qemu Detected",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      rooted: {
        key: "Rooted",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      emulation_detected: {
        key: "Emulation Detected",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // ip/dt: all
      bot_vpn_proxy_tor: {
        key: "BOT, VPN, PROXY, & TOR",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // email
      email_disposable: {
        key: "Disposable",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_honeypot: {
        key: "Honeypot",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_deliverability_high: {
        key: "Deliverablity: High",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_deliverability_medium: {
        key: "Deliverablity: Medium",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_deliverability_low: {
        key: "Deliverablity: Low",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_frequent_complainer: {
        key: "Frequent Complainer",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_catch_all: {
        key: "Catch All",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_generic: {
        key: "Generic",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_common: {
        key: "Common Domain",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_suspect: {
        key: "Suspect",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_domain_velocity_high: {
        key: "Domain Velocity: High",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_domain_velocity_medium: {
        key: "Domain Velocity: Medium",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_domain_velocity_low: {
        key: "Domain Velocity: Low",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // email_conversion_status: {
      //   key: "Conversion Status",
      //   total: 0,
      //   f90: 0,
      //   f80: 0,
      //   diff_total: 0,
      //   diff_f90: 0,
      //   diff_f80: 0,
      // },
      email_spam_trap_score_high: {
        key: "Spam Trap Score: High",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_spam_trap_score_medium: {
        key: "Spam Trap Score: Medium",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      email_spam_trap_score_low: {
        key: "Spam Trap Score: Low",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // phone risky
      phone_active: {
        key: "Active",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      phone_risky: {
        key: "Risky",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      voip: {
        key: "Voip",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      phone_status: {
        key: "Phone Status Active",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      do_not_call: {
        key: "Do Not Call Numbers",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      // URL
      unsafe: {
        key: "Unsafe Website",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      dns_valid: {
        key: "Websites With Valid DNS Entries",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      invalid_dns: {
        key: "Websites With Invalid DNS Entries",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      suspicious: {
        key: "Suspicious Websites",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      phishing: {
        key: "Websites With Suspected Phishing",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      malware: {
        key: "Websites With Suspected Malware",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      parking: {
        key: "Parked Websites",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      spamming: {
        key: "Websites With Suspected Spamming",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      adult: {
        key: "Websites With Suspected Adult Content",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
      redirected: {
        key: "Websites Being Redirected",
        total: 0,
        f90: 0,
        f80: 0,
        diff_total: 0,
        diff_f90: 0,
        diff_f80: 0,
      },
    });
  });
}

function get_connections_object() {
  return new Promise(async (resolve) => {
    resolve({
      residential: await get_indicators_object(),
      mobile: await get_indicators_object(),
      data_center: await get_indicators_object(),
      corporate: await get_indicators_object(),
      education: await get_indicators_object(),
    });
  });
}

function get_device_connections_object() {
  return new Promise(async (resolve) => {
    resolve({
      mobile_2g: await get_indicators_object(),
      mobile_3g: await get_indicators_object(),
      mobile_4g: await get_indicators_object(),
      mobile_data: await get_indicators_object(),
      no_internet: await get_indicators_object(),
      unknown: await get_indicators_object(),
      wifi: await get_indicators_object(),
      wireless: await get_indicators_object(),
    });
  });
}

function create_browser_array(BROWSER_IMPORTS) {
  return new Promise(async (resolve) => {
    const BROWSER_ARRAY = [];
    for (let x = 0; x < BROWSER_IMPORTS.length; x++) {
      const IP = await get_indicators_object();
      const CONNECTION_TYPE = await get_connections_object();
      const BROWSER = {
        browser: BROWSER_IMPORTS[x],
        IP,
        CONNECTION_TYPE,
      };
      BROWSER_ARRAY.push(BROWSER);
      if (x === BROWSER_IMPORTS.length - 1) resolve(BROWSER_ARRAY);
    }
  });
}

function create_os_array(OS_IMPORTS) {
  return new Promise(async (resolve) => {
    const OS_ARRAY = [];
    for (let x = 0; x < OS_IMPORTS.length; x++) {
      const IP = await get_indicators_object();
      const CONNECTION_TYPE = await get_connections_object();
      const OPERATING_SYSTEM = {
        os: OS_IMPORTS[x],
        IP,
        CONNECTION_TYPE,
      };
      OS_ARRAY.push(OPERATING_SYSTEM);
      if (x === OS_IMPORTS.length - 1) resolve(OS_ARRAY);
    }
  });
}

function create_country_array(COUNTRY_IMPORT) {
  return new Promise(async (resolve) => {
    const COUNTRY_ARRAY = [];
    for (let x = 0; x < COUNTRY_IMPORT.length; x++) {
      const IP = await get_indicators_object();
      const CONNECTION_TYPE = await get_connections_object();
      const COUNTRY = {
        country: COUNTRY_IMPORT[x],
        IP,
        CONNECTION_TYPE,
      };
      COUNTRY_ARRAY.push(COUNTRY);
      if (x === COUNTRY_IMPORT.length - 1) resolve(COUNTRY_ARRAY);
    }
  });
}

function create_fraud_array(FRAUD_IMPORT) {
  return new Promise(async (resolve) => {
    const COUNTRY_ARRAY = [];
    for (let x = 0; x < FRAUD_IMPORT.length; x++) {
      const IP = await get_indicators_object();
      const CONNECTION_TYPE = await get_connections_object();
      const COUNTRY = {
        fraud_reason: FRAUD_IMPORT[x],
        IP,
        CONNECTION_TYPE,
      };
      COUNTRY_ARRAY.push(COUNTRY);
      if (x === FRAUD_IMPORT.length - 1) resolve(COUNTRY_ARRAY);
    }
  });
}

function create_model_array(MODELS) {
  return new Promise(async (resolve) => {
    const MODEL_ARRAY = [];
    for (let x = 0; x < MODELS.length; x++) {
      const IP = await get_indicators_object();
      const CONNECTION_TYPE = await get_connections_object();
      const COUNTRY = {
        model: MODELS[x],
        IP,
        CONNECTION_TYPE,
      };
      MODEL_ARRAY.push(COUNTRY);
      if (x === MODELS.length - 1) resolve(MODEL_ARRAY);
    }
  });
}

module.exports = { assemble_ip_reports_array };
