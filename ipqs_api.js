const AXIOS = require("./axios");

class ipqs extends response_messages {
  static IPQS_BASE_URL = "https://www.ipqualityscore.com/api/json/";
  api_key = "";
  response_type = "";
  results = [];

  constructor(api_key, response_type) {
    this.api_key = api_key;
    this.response_type = response_type;
  }

  set() {
    api_key = (key) => {
      this.api_key = key;
    };
    response_type = (response_type) => {
      this.response_type = response_type;
    };
  }

  get() {
    api_key = () => {
      return this.api_key;
    };
    response_type = () => {
      return this.response_type;
    };
  }

  get_ip = (ip_data) => {
    // accepts an array of objects, primary field is ip, additional data will be appended to repsonse
    // eg. { ip: 192.168.1.1, user: qyser, email: test@test.com}
    return new Promise(async (resolve, reject) => {
      if (!this.is_api_key_valid(this.api_key)) reject("Invalid API Key");
      if (this.response_type === "json" || this.response_type === "xml")
        reject("Response format not set");
      try {
        const IPQS_DATA = await ip_data.map((ip) => {
          const IPQS_IP_DATA = new Promise(async (resolve, reject) => {
            const URL = `${this.IPQS_BASE_URL}/ip/${this.api_key}/${ip.ip}`;
            const IP_DATA = await this.call_ipqs(URL);
            IP_DATA.original_value = ip.ip;
            resolve(IP_DATA);
          });
          return IPQS_IP_DATA;
        });
        resolve(("IP data", IPQS_DATA));
      } catch (error) {
        reject("Error calling API");
      }
    });
  };

  static is_api_key_valid(api_key) {
    if (api_key !== "" && api_key.length === 32) {
      return true;
    } else {
      return false;
    }
  }

  static call_ipqs(url) {
    return new Promise(async (resolve, reject) => {
      try {
        const RESPONSE = AXIOS.get(url);
        const DATA = RESPONSE.data;
        resolve(DATA);
      } catch (error) {
        reject(error);
      }
    });
  }
}

module.exports = { ipqs };
