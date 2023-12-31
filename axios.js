const AXIOS_RAW = require("AXIOS");

const AXIOS = AXIOS_RAW.create({});

const max_requests = 5;
const ms_interval = 10;
const pending_requests = 0;

AXIOS.interceptors.request.use(function (config) {
  return new Promise((resolve, reject) => {
    let interval = setInterval(() => {
      if (pending_requests < max_requests) {
        pending_requests++;
        clearInterval(interval);
        resolve(config);
      }
    }, ms_interval);
  });
});

AXIOS.interceptors.response.use(
  function (response) {
    pending_requests = Math.max(0, pending_requests - 1);
    return Promise.resolve(response);
  },
  function (error) {
    pending_requests = Math.max(0, pending_requests - 1);
    return Promise.reject(error);
  }
);

module.exports = AXIOS;
