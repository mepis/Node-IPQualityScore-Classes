const indicators = require("./data/reports_indicators");

var IP_REPORT;
/* eslint-disable */

const INDICATORS = [
  // shared
  "totals",
  "valid",
  "recent_abuse",

  // IP
  // singles
  "bot",
  "proxy",
  "vpn",
  "active_vpn",
  "tor",
  "active_tor",
  "leaked",
  "abuse_velocity_high",
  "abuse_velocity_medium",
  "abuse_velocity_low",
  // doubles
  "bot_vpn",
  "bot_proxy",
  "bot_tor",
  "vpn_proxy",
  "vpn_tor",
  // triples
  "bot_vpn_proxy",
  "bot_proxy_tor",
  // email
  "email_disposable",
  "email_honeypot",
  "email_deliverability_high",
  "email_deliverability_medium",
  "email_deliverability_low",
  "email_frequent_complainer",
  "email_catch_all",
  "email_generic",
  "email_suspect",
  "email_common",
  "email_domain_velocity_high",
  "email_domain_velocity_medium",
  "email_domain_velocity_low",
  "user_activity_high",
  "user_activity_medium",
  "user_activity_low",
  "email_conversion_status",
  "email_spam_trap_score_high",
  "email_spam_trap_score_medium",
  "email_spam_trap_score_low",
  // mobile tracker
  "qemu_detected",
  "rooted",
  "emulation_detected",
  "phone_active",
  "phone_risky",
  "voip",
  "phone_status",
  "do_not_call",
  //url
  "unsafe",
  "dns_valid",
  "invalid_dns",
  "suspicious",
  "phishing",
  "malware",
  "parking",
  "spamming",
  "adult",
  "redirected",
];

const TOTALS = ["total", "f90", "f80"];

const CONNECTION_TYPES = [
  "residential",
  "mobile",
  "data_center",
  "corporate",
  "education",
];
const DEVICE_CONNECTION_TYPES = [
  "mobile_2g",
  "mobile_3g",
  "mobile_4g",
  "mobile_data",
  "no_internet",
  "unknown",
  "wifi",
  "wireless",
];

let data;

async function compile_metrics() {
  return new Promise(async (resolve) => {
    // common data

    for (let row = 0; row < data.length; row++) {
      // #########################################
      // Start Init Checks
      // #########################################
      var CHECKS = await indicators.indicators(data[row]);
      let BROWSER;
      let MODEL;
      let CPU;
      let BRAND;
      let OPERATING_SYSTEM;

      if (data[row].browser && data[row].browser !== undefined)
        BROWSER = data[row].browser;

      if (data[row].model && data[row].model !== undefined)
        MODEL = data[row].model;

      if (data[row].cpu_model && data[row].cpu_model !== undefined)
        CPU = data[row].cpu_model;

      if (data[row].brand && data[row].brand !== undefined)
        BRAND = data[row].brand;

      if (
        data[row].operating_system &&
        data[row].operating_system !== undefined
      )
        OPERATING_SYSTEM = data[row].operating_system;

      let browser_index;
      let os_index;
      let country_index;
      let fraud_index;
      let model_index;
      let browser_array_type;
      let os_array_type;
      let model_array_type;
      let os_check = false;
      let browser_check = false;
      let model_check = false;
      let fraud_reasons = [];

      if (
        !CHECKS.isUnknownOS &&
        OPERATING_SYSTEM !== undefined &&
        OPERATING_SYSTEM !== "N/A"
      ) {
        os_check = true;
      }

      if (
        !CHECKS.isUnknownBrowser &&
        BROWSER !== undefined &&
        BROWSER !== "N/A"
      ) {
        browser_check = true;
      }

      if (!CHECKS.isUnknownModel && MODEL !== undefined && MODEL !== "N/A") {
        model_array_type = "MODEL_ARRAY";
        model_index = await get_index(IP_REPORT.ip_reports.MODEL_ARRAY, MODEL);
        if (model_index > 0) {
          model_check = true;
        }
      }

      if (CHECKS.isDesktopBrowser) {
        browser_array_type = "DESKTOP_BROWSER_ARRAY";
        browser_index = await get_index(
          IP_REPORT.ip_reports.DESKTOP_BROWSER_ARRAY,
          BROWSER
        );
      }
      if (CHECKS.isMobileBrowser) {
        browser_array_type = "MOBILE_BROWSER_ARRAY";
        browser_index = await get_index(
          IP_REPORT.ip_reports.MOBILE_BROWSER_ARRAY,
          BROWSER
        );
      }

      if (CHECKS.isOtherBrowser) {
        browser_array_type = "OTHER_BROWSER_ARRAY";
        browser_index = await get_index(
          IP_REPORT.ip_reports.OTHER_BROWSER_ARRAY,
          BROWSER
        );
      }

      if (CHECKS.isDesktopOS) {
        os_array_type = "DESKTOP_OS_ARRAY";
        os_index = await get_index(
          IP_REPORT.ip_reports.DESKTOP_OS_ARRAY,
          OPERATING_SYSTEM
        );
      }
      if (CHECKS.isMobileOS) {
        os_array_type = "MOBILE_OS_ARRAY";
        os_index = await get_index(
          IP_REPORT.ip_reports.MOBILE_OS_ARRAY,
          OPERATING_SYSTEM
        );
      }

      if (!CHECKS.isUnknownCountry) {
        if (CHECKS.country !== "N/A") {
          if (CHECKS.country !== false) {
            country_index = await get_index(
              IP_REPORT.ip_reports.COUNTRY_ARRAY,
              CHECKS.country
            );
          }
        }
      }

      // ##########################################
      // Unknown Objects
      // ##########################################

      if (CHECKS.isUnknownModel) {
        IP_REPORT.ip_reports.unknown_model.push({
          brand: BRAND,
          model: MODEL,
          cpu: CPU,
          entry: `{brand: "${BRAND}", model: "${MODEL}", cpu: "${CPU}"},`,
          data: data[row],
        });
        IP_REPORT.ip_reports.users_with_unknown_devices.push(data[row]);
      }

      if (CHECKS.isUnknownBrowser) {
        IP_REPORT.ip_reports.unknown_browsers.push({
          browser: `"${BROWSER}",`,
        });
      }

      if (CHECKS.isUnknownActiveVPN) {
        IP_REPORT.ip_reports.unknown_active_vpns.push({
          active_vpn: `"${data[row].isp}",`,
        });
      }

      if (CHECKS.isUnknownOS) {
        IP_REPORT.ip_reports.unknown_os.push({
          os: `"${OPERATING_SYSTEM}",`,
        });
      }

      if (CHECKS.isUnknownCountry) {
        IP_REPORT.ip_reports.unknown_countries.push({
          country: `"${CHECKS.country}",`,
        });
      }

      if (data[row].fraud_reasons && data[row].fraud_reasons !== undefined) {
        const LINE_FRAUD_REASON = data[row].fraud_reasons.split(".");
        fraud_reasons = LINE_FRAUD_REASON;
      }

      // #########################################
      // End Init Checks
      // #########################################

      // #########################################
      // Start Functions
      // #########################################
      function set_indicator(
        array_type,
        entry,
        section,
        connection_type,
        gross,
        quantity
      ) {
        if (connection_type !== null) {
          IP_REPORT.ip_reports[array_type][entry][section][connection_type][
            gross
          ][quantity] += 1;
        } else {
          IP_REPORT.ip_reports[array_type][entry][section][gross][
            quantity
          ] += 1;
        }
        return true;
      }

      async function add_total(entry, quantity) {
        IP_REPORT.ip_reports.IP[INDICATORS[entry]][TOTALS[quantity]] += 1;
        if (browser_check) {
          set_indicator(
            browser_array_type,
            browser_index,
            "IP",
            null,
            INDICATORS[entry],
            TOTALS[quantity]
          );
        }

        if (model_check) {
          set_indicator(
            model_array_type,
            model_index,
            "IP",
            null,
            INDICATORS[entry],
            TOTALS[quantity]
          );
        }

        if (os_check)
          set_indicator(
            os_array_type,
            os_index,
            "IP",
            null,
            INDICATORS[entry],
            TOTALS[quantity]
          );

        if (!CHECKS.isUnknownCountry && CHECKS.country !== false)
          set_indicator(
            "COUNTRY_ARRAY",
            country_index,
            "IP",
            null,
            INDICATORS[entry],
            TOTALS[quantity]
          );
        if (fraud_reasons.length > 0) {
          fraud_reasons.map(async (line) => {
            if (!KNOWN_FRAUD_REASONS.includes(line)) {
              if (!IP_REPORT.ip_reports.unknown_fraud_reasons.includes(line)) {
                IP_REPORT.ip_reports.unknown_fraud_reasons.push({
                  fraud_reason: `"${line}",`,
                });
              }
            } else {
              fraud_index = await get_index(
                IP_REPORT.ip_reports.FRAUD_ARRAY,
                line
              );
              set_indicator(
                "FRAUD_ARRAY",
                fraud_index,
                "IP",
                null,
                INDICATORS[entry],
                TOTALS[quantity]
              );
            }
          });
        }
      }

      async function add_connection_type_total(connection, entry, quantity) {
        IP_REPORT.ip_reports.CONNECTION_TYPE[CONNECTION_TYPES[connection]][
          INDICATORS[entry]
        ][TOTALS[quantity]] += 1;
        if (browser_check)
          set_indicator(
            browser_array_type,
            browser_index,
            "CONNECTION_TYPE",
            CONNECTION_TYPES[connection],
            INDICATORS[entry],
            TOTALS[quantity]
          );

        if (model_check)
          set_indicator(
            model_array_type,
            model_index,
            "CONNECTION_TYPE",
            CONNECTION_TYPES[connection],
            INDICATORS[entry],
            TOTALS[quantity]
          );

        if (os_check)
          set_indicator(
            os_array_type,
            os_index,
            "CONNECTION_TYPE",
            CONNECTION_TYPES[connection],
            INDICATORS[entry],
            TOTALS[quantity]
          );

        if (CHECKS.isUnknownCountry !== true) {
          set_indicator(
            "COUNTRY_ARRAY",
            country_index,
            "CONNECTION_TYPE",
            CONNECTION_TYPES[connection],
            INDICATORS[entry],
            TOTALS[quantity]
          );
        }

        if (fraud_reasons.length > 0) {
          fraud_reasons.map(async (line) => {
            if (KNOWN_FRAUD_REASONS.includes(line)) {
              fraud_index = await get_index(
                IP_REPORT.ip_reports.FRAUD_ARRAY,
                line
              );
              set_indicator(
                "FRAUD_ARRAY",
                fraud_index,
                "CONNECTION_TYPE",
                CONNECTION_TYPES[connection],
                INDICATORS[entry],
                TOTALS[quantity]
              );
            }
          });
        }
      }

      async function add_device_onnection_type_total(
        connection,
        entry,
        quantity
      ) {
        IP_REPORT.ip_reports.DEVICE_CONNECTION_TYPE[
          DEVICE_CONNECTION_TYPES[connection]
        ][INDICATORS[entry]][TOTALS[quantity]] += 1;
      }

      function check_type(secondary_check, entry, quantity, connection) {
        // URL
        if (CHECKS.is_unsafe && INDICATORS[entry] === "unsafe") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_dns_valid && INDICATORS[entry] === "dns_valid") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_dns_invalid && INDICATORS[entry] === "invalid_dns") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_suspicious && INDICATORS[entry] === "suspicious") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_phishing && INDICATORS[entry] === "phishing") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_malware && INDICATORS[entry] === "malware") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_parked && INDICATORS[entry] === "parking") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_spam && INDICATORS[entry] === "spamming") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_adult && INDICATORS[entry] === "adult") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.is_redirected && INDICATORS[entry] === "redirected") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        // Phone
        if (CHECKS.isLineActive && INDICATORS[entry] === "phone_status") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.isDNC && INDICATORS[entry] === "do_not_call") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.isRisky && INDICATORS[entry] === "phone_risky") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.isActive && INDICATORS[entry] === "phone_active") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (
          CHECKS.user_activity_high &&
          INDICATORS[entry] === "user_activity_high"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.user_activity_medium &&
          INDICATORS[entry] === "user_activity_medium"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (
          CHECKS.user_activity_low &&
          INDICATORS[entry] === "user_activity_low"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        if (CHECKS.isVoip && INDICATORS[entry] === "voip") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
        // IP/ Device Tracker/ Mobile Tracker Shared
        if (
          CHECKS.isHighAbuseVelocity &&
          INDICATORS[entry] === "abuse_velocity_high"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isMediumAbuseVelocity &&
          INDICATORS[entry] === "abuse_velocity_medium"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isLowAbuseVelocity &&
          INDICATORS[entry] === "abuse_velocity_low"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isBot && INDICATORS[entry] === "bot") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isVPN && INDICATORS[entry] === "vpn") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isProxy && INDICATORS[entry] === "proxy") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isTor && INDICATORS[entry] === "tor") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isBot &&
          CHECKS.isProxy &&
          INDICATORS[entry] === "bot_proxy"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isBot && CHECKS.isTor && INDICATORS[entry] === "bot_tor") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        // mobile tracker
        if (CHECKS.isQemu && INDICATORS[entry] === "qemu_detected") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isQemu && INDICATORS[entry] === "qemu_detected") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isRooted && INDICATORS[entry] === "rooted") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isEmulationDetected &&
          INDICATORS[entry] === "emulation_detected"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        // Email
        if (CHECKS.isValid && INDICATORS[entry] === "valid") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isDisposable && INDICATORS[entry] === "email_disposable") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isGeneric && INDICATORS[entry] === "email_generic") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isCommon && INDICATORS[entry] === "email_common") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isHoneypot && INDICATORS[entry] === "email_honeypot") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.deliverability_high &&
          INDICATORS[entry] === "email_deliverability_high"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.deliverability_medium &&
          INDICATORS[entry] === "email_deliverability_medium"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.deliverability_low &&
          INDICATORS[entry] === "email_deliverability_low"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isFrequent_complainer &&
          INDICATORS[entry] === "email_frequent_complainer"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.spam_trap_score_high &&
          INDICATORS[entry] === "email_spam_trap_score_high"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.spam_trap_score_medium &&
          INDICATORS[entry] === "email_spam_trap_score_medium"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.spam_trap_score_low &&
          INDICATORS[entry] === "email_spam_trap_score_low"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.domain_velocity_high &&
          INDICATORS[entry] === "email_domain_velocity_high"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.domain_velocity_medium &&
          INDICATORS[entry] === "domain_velocity_medium"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.domain_velocity_low &&
          INDICATORS[entry] === "email_domain_velocity_low"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isCatch_all && INDICATORS[entry] === "email_catch_all") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isSuspect && INDICATORS[entry] === "email_suspect") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isRecent_abuse && INDICATORS[entry] === "recent_abuse") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        // IP
        if (INDICATORS[entry] === "totals") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isActiveVPN && INDICATORS[entry] === "active_vpn") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isActiveTor && INDICATORS[entry] === "active_tor") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isLeaked && INDICATORS[entry] === "leaked") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isBot && CHECKS.isVPN && INDICATORS[entry] === "bot_vpn") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isVPN &&
          CHECKS.isProxy &&
          INDICATORS[entry] === "vpn_proxy"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (CHECKS.isVPN && CHECKS.isTor && INDICATORS[entry] === "vpn_tor") {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isBot &&
          CHECKS.isVPN &&
          CHECKS.isProxy &&
          INDICATORS[entry] === "bot_vpn_proxy"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isBot &&
          CHECKS.isProxy &&
          CHECKS.isTor &&
          INDICATORS[entry] === "bot_proxy_tor"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }

        if (
          CHECKS.isBot &&
          CHECKS.isVPN &&
          CHECKS.isProxy &&
          CHECKS.isTor &&
          INDICATORS[entry] === "bot_vpn_proxy_tor"
        ) {
          divert_report_entry(secondary_check, connection, entry, quantity);
        }
      }

      function divert_report_entry(
        secondary_check,
        connection,
        entry,
        quantity
      ) {
        if (connection === null) {
          add_total(entry, quantity);
        }
        if (secondary_check === "connection_type") {
          add_connection_type_total(connection, entry, quantity);
        }
        if (secondary_check === "device_connection_type") {
          add_device_onnection_type_total(connection, entry, quantity);
        }
      }

      function check_device_connection_type(
        secondary_check,
        entry,
        quantity,
        connection
      ) {
        if (
          CHECKS.is_mobile_2g &&
          DEVICE_CONNECTION_TYPES[connection] === "mobile_2g"
        ) {
          check_type(secondary_check, entry, quantity, connection);
        }

        if (
          CHECKS.is_mobile_3g &&
          DEVICE_CONNECTION_TYPES[connection] === "mobile_3g"
        ) {
          check_type(secondary_check, entry, quantity, connection);
        }

        if (
          CHECKS.is_mobile_4g &&
          DEVICE_CONNECTION_TYPES[connection] === "mobile_4g"
        ) {
          check_type(secondary_check, entry, quantity, connection);
        }

        if (
          CHECKS.is_mobile_data[row] &&
          DEVICE_CONNECTION_TYPES[connection] === "mobile_data[row]"
        ) {
          check_type(secondary_check, entry, quantity, connection);
        }

        if (
          CHECKS.is_no_internet &&
          DEVICE_CONNECTION_TYPES[connection] === "no_internet"
        ) {
          check_type(secondary_check, entry, quantity, connection);
        }

        if (
          CHECKS.is_unknown &&
          DEVICE_CONNECTION_TYPES[connection] === "unknown"
        ) {
          check_type(secondary_check, entry, quantity, connection);
        }

        if (CHECKS.is_wifi && DEVICE_CONNECTION_TYPES[connection] === "wifi") {
          check_type(secondary_check, entry, quantity, connection);
        }

        if (
          CHECKS.is_wireless &&
          DEVICE_CONNECTION_TYPES[connection] === "wireless"
        ) {
          check_type(secondary_check, entry, quantity, connection);
        }
      }

      // #########################################
      // End Functions
      // #########################################
      for (let entry = 0; entry < INDICATORS.length; entry++) {
        for (let quantity = 0; quantity < TOTALS.length; quantity++) {
          if (TOTALS[quantity] === "total") {
            check_type(null, entry, quantity, null);
          }

          if (CHECKS.is90 && TOTALS[quantity] === "f90") {
            check_type(null, entry, quantity, null);
          }

          if (CHECKS.is80 && TOTALS[quantity] === "f80") {
            check_type(null, entry, quantity, null);
          }

          //###############################
          // Start Device Connection Types
          //###############################
          for (
            let device_connection = 0;
            device_connection < DEVICE_CONNECTION_TYPES.length;
            device_connection++
          ) {
            let secondary_check = "device_connection_type";
            if (TOTALS[quantity] === "total") {
              check_device_connection_type(
                secondary_check,
                entry,
                quantity,
                device_connection
              );
            }
            if (CHECKS.is90 && TOTALS[quantity] === "f90") {
              check_device_connection_type(
                secondary_check,
                entry,
                quantity,
                device_connection
              );
            }
            if (CHECKS.is80 && TOTALS[quantity] === "f80") {
              check_device_connection_type(
                secondary_check,
                entry,
                quantity,
                device_connection
              );
            }
          }
          //###############################
          // Start Connection Types
          //############################### DEVICE_CONNECTION_TYPES

          for (
            let connection = 0;
            connection < CONNECTION_TYPES.length;
            connection++
          ) {
            let secondary_check = "connection_type";
            if (TOTALS[quantity] === "total") {
              if (
                CHECKS.isResiential &&
                CONNECTION_TYPES[connection] === "residential"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isdataCenter &&
                CONNECTION_TYPES[connection] === "data[row]_center"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isMobile &&
                CONNECTION_TYPES[connection] === "mobile"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isEducation &&
                CONNECTION_TYPES[connection] === "education"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isCorporate &&
                CONNECTION_TYPES[connection] === "corporate"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }
            }

            if (CHECKS.is90 && TOTALS[quantity] === "f90") {
              if (
                CHECKS.isResiential &&
                CONNECTION_TYPES[connection] === "residential"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isdataCenter &&
                CONNECTION_TYPES[connection] === "data[row]_center"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isMobile &&
                CONNECTION_TYPES[connection] === "mobile"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isEducation &&
                CONNECTION_TYPES[connection] === "education"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isCorporate &&
                CONNECTION_TYPES[connection] === "corporate"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }
            }

            if (CHECKS.is80 && TOTALS[quantity] === "f80") {
              if (
                CHECKS.isResiential &&
                CONNECTION_TYPES[connection] === "residential"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isdataCenter &&
                CONNECTION_TYPES[connection] === "data[row]_center"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isMobile &&
                CONNECTION_TYPES[connection] === "mobile"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isEducation &&
                CONNECTION_TYPES[connection] === "education"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }

              if (
                CHECKS.isCorporate &&
                CONNECTION_TYPES[connection] === "corporate"
              ) {
                check_type(secondary_check, entry, quantity, connection);
              }
            }
          }
        } // end quantity loop
      } // end indicator loop
      if (row === data.length - 1) {
        resolve(IP_REPORT);
      }
    } // end for loop
  });
}

function get_index(object_array, entry) {
  return new Promise(async (resolve) => {
    if (object_array === null) {
      resolve(-1);
    }
    for (let line = 0; line < object_array.length; line++) {
      if (object_array[line].os && object_array[line].os === entry) {
        object_array = null;
        resolve(line);
        break;
      } else if (
        object_array[line].country &&
        object_array[line].country === entry
      ) {
        object_array = null;
        resolve(line);
        break;
      } else if (
        object_array[line].browser &&
        object_array[line].browser === entry
      ) {
        object_array = null;
        resolve(line);
        break;
      } else if (
        object_array[line].fraud_reason &&
        object_array[line].fraud_reason === entry
      ) {
        object_array = null;
        resolve(line);
        break;
      } else if (
        object_array[line].model &&
        object_array[line].model.model === entry
      ) {
        object_array = null;
        resolve(line);
        break;
      } else if (object_array === null || line === object_array.length - 1) {
        object_array = null;
        resolve(-1);
        break;
      }
    }
  });
}
