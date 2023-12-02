const MOBILE_BROWSERS = [
  "Aloha 18.7.0",
  "Aloha 21.5.0",
  "Aloha 21.6.0",
  "Aloha 22.2.0",
  "Aloha 22.5.0",
  "Aloha Browser 3.1",
  "Aloha Browser 4.1",
  "Aloha Browser 4.10",
  "Aloha Browser 4.11",
  "Aloha Browser 4.3",
  "Aloha Browser 4.4",
  "Aloha Browser 4.5",
  "Aloha Browser 4.6",
  "Aloha Browser 4.7",
  "Aloha Browser 4.8",
  "Aloha Browser 4.9",
  "Android Browser ",
  "Android Browser N/A",
  "Android Browser",
  "Chrome Mobile 100.0",
  "Chrome Mobile 101.0",
  "Chrome Mobile 102.0",
  "Chrome Mobile 103.0",
  "Chrome Mobile 104.0",
  "Chrome Mobile 105.0",
  "Chrome Mobile 106.0",
  "Chrome Mobile 107.0",
  "Chrome Mobile 108.0",
  "Chrome Mobile 109.0",
  "Chrome Mobile 110.0",
  "Chrome Mobile 111.0",
  "Chrome Mobile 112.0",
  "Chrome Mobile 112.215",
  "Chrome Mobile 113.0",
  "Chrome Mobile 114.0",
  "Chrome Mobile 115.0",
  "Chrome Mobile 116.0",
  "Chrome Mobile 27.0",
  "Chrome Mobile 30.0",
  "Chrome Mobile 34.0",
  "Chrome Mobile 347.0",
  "Chrome Mobile 38.0",
  "Chrome Mobile 40.0",
  "Chrome Mobile 42.0",
  "Chrome Mobile 43.0",
  "Chrome Mobile 44.0",
  "Chrome Mobile 45.0",
  "Chrome Mobile 46.0",
  "Chrome Mobile 47.0",
  "Chrome Mobile 48.0",
  "Chrome Mobile 49.0",
  "Chrome Mobile 50.0",
  "Chrome Mobile 51.0",
  "Chrome Mobile 52.0",
  "Chrome Mobile 53.0",
  "Chrome Mobile 54.0",
  "Chrome Mobile 55.0",
  "Chrome Mobile 56.0",
  "Chrome Mobile 57.0",
  "Chrome Mobile 58.0",
  "Chrome Mobile 59.0",
  "Chrome Mobile 60.0",
  "Chrome Mobile 61.0",
  "Chrome Mobile 62.0",
  "Chrome Mobile 63.0",
  "Chrome Mobile 64.0",
  "Chrome Mobile 65.0",
  "Chrome Mobile 66.0",
  "Chrome Mobile 67.0",
  "Chrome Mobile 68.0",
  "Chrome Mobile 69.0",
  "Chrome Mobile 70.0",
  "Chrome Mobile 71.0",
  "Chrome Mobile 72.0",
  "Chrome Mobile 73.0",
  "Chrome Mobile 74.0",
  "Chrome Mobile 75.0",
  "Chrome Mobile 76.0",
  "Chrome Mobile 77.0",
  "Chrome Mobile 77",
  "Chrome Mobile 78.0",
  "Chrome Mobile 79.0",
  "Chrome Mobile 80.0",
  "Chrome Mobile 81.0",
  "Chrome Mobile 83.0",
  "Chrome Mobile 84.0",
  "Chrome Mobile 85.0",
  "Chrome Mobile 86.0",
  "Chrome Mobile 87.0",
  "Chrome Mobile 88.0",
  "Chrome Mobile 89.0",
  "Chrome Mobile 90.0",
  "Chrome Mobile 91.0",
  "Chrome Mobile 92.0",
  "Chrome Mobile 93.0",
  "Chrome Mobile 94.0",
  "Chrome Mobile 95.0",
  "Chrome Mobile 96.0",
  "Chrome Mobile 97.0",
  "Chrome Mobile 98.0",
  "Chrome Mobile 99.0",
  "Chrome Mobile iOS 1.0",
  "Chrome Mobile iOS 100.0",
  "Chrome Mobile iOS 101.0",
  "Chrome Mobile iOS 102.0",
  "Chrome Mobile iOS 103.0",
  "Chrome Mobile iOS 104.0",
  "Chrome Mobile iOS 104",
  "Chrome Mobile iOS 105.0",
  "Chrome Mobile iOS 105",
  "Chrome Mobile iOS 106.0",
  "Chrome Mobile iOS 107.0",
  "Chrome Mobile iOS 107",
  "Chrome Mobile iOS 108.0",
  "Chrome Mobile iOS 108",
  "Chrome Mobile iOS 109.0",
  "Chrome Mobile iOS 109",
  "Chrome Mobile iOS 110.0",
  "Chrome Mobile iOS 110",
  "Chrome Mobile iOS 111",
  "Chrome Mobile iOS 112.0",
  "Chrome Mobile iOS 112",
  "Chrome Mobile iOS 113.0",
  "Chrome Mobile iOS 113",
  "Chrome Mobile iOS 114.0",
  "Chrome Mobile iOS 114",
  "Chrome Mobile iOS 115.0",
  "Chrome Mobile iOS 115",
  "Chrome Mobile iOS 19.0",
  "Chrome Mobile iOS 47.0",
  "Chrome Mobile iOS 49.0",
  "Chrome Mobile iOS 51.0",
  "Chrome Mobile iOS 62.0",
  "Chrome Mobile iOS 67.0",
  "Chrome Mobile iOS 68.0",
  "Chrome Mobile iOS 69.0",
  "Chrome Mobile iOS 70.0",
  "Chrome Mobile iOS 71.0",
  "Chrome Mobile iOS 72.0",
  "Chrome Mobile iOS 73.0",
  "Chrome Mobile iOS 74.0",
  "Chrome Mobile iOS 75.0",
  "Chrome Mobile iOS 76.0",
  "Chrome Mobile iOS 77.0",
  "Chrome Mobile iOS 78.0",
  "Chrome Mobile iOS 79.0",
  "Chrome Mobile iOS 80.0",
  "Chrome Mobile iOS 81.0",
  "Chrome Mobile iOS 83.0",
  "Chrome Mobile iOS 84.0",
  "Chrome Mobile iOS 85.0",
  "Chrome Mobile iOS 86.0",
  "Chrome Mobile iOS 87.0",
  "Chrome Mobile iOS 90.0",
  "Chrome Mobile iOS 91.0",
  "Chrome Mobile iOS 92.0",
  "Chrome Mobile iOS 93.0",
  "Chrome Mobile iOS 94.0",
  "Chrome Mobile iOS 95.0",
  "Chrome Mobile iOS 96.0",
  "Chrome Mobile iOS 97.0",
  "Chrome Mobile iOS 98.0",
  "Chrome Mobile iOS 99.0",
  "Facebook 151.0",
  "Facebook 158.0",
  "Facebook 190.0",
  "Facebook 192.0",
  "Facebook 194.0",
  "Facebook 196.0",
  "Facebook 197.1",
  "Facebook 198.0",
  "Facebook 202.0",
  "Facebook 205.0",
  "Facebook 208.0",
  "Facebook 210.0",
  "Facebook 226.0",
  "Facebook 229.0",
  "Facebook 233.0",
  "Facebook 237.0",
  "Facebook 238.0",
  "Facebook 241.0",
  "Facebook 242.0",
  "Facebook 243.0",
  "Facebook 244.0",
  "Facebook 247.0",
  "Facebook 248.1",
  "Facebook 250.0",
  "Facebook 251.0",
  "Facebook 252.0",
  "Facebook 254.0",
  "Facebook 255.0",
  "Facebook 256.0",
  "Facebook 258.0",
  "Facebook 259.0",
  "Facebook 260.0",
  "Facebook 261.0",
  "Facebook 262.0",
  "Facebook 263.0",
  "Facebook 264.0",
  "Facebook 265.0",
  "Facebook 266.0",
  "Facebook 268.0",
  "Facebook 268.1",
  "Facebook 269.0",
  "Facebook 270.0",
  "Facebook 270.1",
  "Facebook 271.0",
  "Facebook 272.0",
  "Facebook 273.0",
  "Facebook 274.0",
  "Facebook 275.0",
  "Facebook 276.0",
  "Facebook 277.0",
  "Facebook 278.0",
  "Facebook 279.0",
  "Facebook 280.0",
  "Facebook 281.0",
  "Facebook 282.0",
  "Facebook 283.0",
  "Facebook 284.0",
  "Facebook 285.0",
  "Facebook 286.0",
  "Facebook 287.0",
  "Facebook 288.0",
  "Facebook 288.1",
  "Facebook 289.0",
  "Facebook 290.0",
  "Facebook 291.0",
  "Facebook 291.2",
  "Facebook 292.0",
  "Facebook 293.0",
  "Facebook 294.0",
  "Facebook 295.0",
  "Facebook 296.0",
  "Facebook 297.0",
  "Facebook 298.0",
  "Facebook 299.0",
  "Facebook 300.0",
  "Facebook 300.1",
  "Facebook 300.2",
  "Facebook 301.0",
  "Facebook 302.0",
  "Facebook 303.0",
  "Facebook 304.0",
  "Facebook 305.0",
  "Facebook 305.1",
  "Facebook 306.0",
  "Facebook 306.1",
  "Facebook 307.0",
  "Facebook 307.1",
  "Facebook 308.0",
  "Facebook 309.0",
  "Facebook 310.0",
  "Facebook 311.0",
  "Facebook 312.0",
  "Facebook 313.0",
  "Facebook 314.0",
  "Facebook 314.1",
  "Facebook 315.0",
  "Facebook 316.0",
  "Facebook 317.0",
  "Facebook 318.0",
  "Facebook 319.0",
  "Facebook 320.0",
  "Facebook 321.0",
  "Facebook 322.0",
  "Facebook 323.0",
  "Facebook 324.0",
  "Facebook 325.0",
  "Facebook 326.0",
  "Facebook 327.0",
  "Facebook 327.1",
  "Facebook 328.0",
  "Facebook 328.1",
  "Facebook 329.0",
  "Facebook 330.0",
  "Facebook 331.0",
  "Facebook 331.1",
  "Facebook 332.0",
  "Facebook 333.0",
  "Facebook 334.0",
  "Facebook 335.0",
  "Facebook 336.0",
  "Facebook 337.0",
  "Facebook 337.1",
  "Facebook 338.0",
  "Facebook 338.1",
  "Facebook 339.0",
  "Facebook 340.0",
  "Facebook 341.0",
  "Facebook 342.0",
  "Facebook 342.1",
  "Facebook 343.0",
  "Facebook 343.1",
  "Facebook 344.0",
  "Facebook 345.0",
  "Facebook 346.0",
  "Facebook 347.0",
  "Facebook 348.0",
  "Facebook 348.2",
  "Facebook 349.0",
  "Facebook 350.0",
  "Facebook 350.1",
  "Facebook 351.0",
  "Facebook 352.0",
  "Facebook 353.0",
  "Facebook 354.0",
  "Facebook 355.0",
  "Facebook 356.0",
  "Facebook 357.0",
  "Facebook 358.0",
  "Facebook 359.0",
  "Facebook 360.0",
  "Facebook 360.1",
  "Facebook 361.0",
  "Facebook 362.0",
  "Facebook 363.0",
  "Facebook 364.0",
  "Facebook 364.1",
  "Facebook 365.0",
  "Facebook 366.0",
  "Facebook 366.1",
  "Facebook 367.0",
  "Facebook 367.2",
  "Facebook 368.0",
  "Facebook 369.0",
  "Facebook 370.0",
  "Facebook 371.0",
  "Facebook 371.1",
  "Facebook 372.0",
  "Facebook 372.1",
  "Facebook 373.0",
  "Facebook 373.2",
  "Facebook 374.0",
  "Facebook 375.1",
  "Facebook 376.0",
  "Facebook 376.1",
  "Facebook 377.0",
  "Facebook 378.2",
  "Facebook 379.0",
  "Facebook 379.1",
  "Facebook 380.0",
  "Facebook 380.1",
  "Facebook 381.0",
  "Facebook 382.0",
  "Facebook 382.1",
  "Facebook 383.0",
  "Facebook 383.1",
  "Facebook 384.0",
  "Facebook 384.1",
  "Facebook 385.0",
  "Facebook 386.0",
  "Facebook 386.1",
  "Facebook 387.0",
  "Facebook 388.0",
  "Facebook 389.0",
  "Facebook 389.1",
  "Facebook 390.0",
  "Facebook 390.1",
  "Facebook 390.2",
  "Facebook 391.0",
  "Facebook 391.1",
  "Facebook 391.2",
  "Facebook 392.0",
  "Facebook 392.2",
  "Facebook 393.0",
  "Facebook 394.0",
  "Facebook 394.1",
  "Facebook 395.0",
  "Facebook 396.0",
  "Facebook 396.1",
  "Facebook 397.0",
  "Facebook 398.0",
  "Facebook 398.1",
  "Facebook 399.0",
  "Facebook 399.3",
  "Facebook 400.0",
  "Facebook 400.1",
  "Facebook 401.0",
  "Facebook 401.1",
  "Facebook 402.0",
  "Facebook 402.1",
  "Facebook 403.0",
  "Facebook 403.1",
  "Facebook 404.0",
  "Facebook 405.0",
  "Facebook 405.1",
  "Facebook 406.0",
  "Facebook 407.0",
  "Facebook 407.1",
  "Facebook 408.0",
  "Facebook 408.1",
  "Facebook 409.0",
  "Facebook 409.1",
  "Facebook 410.0",
  "Facebook 411.0",
  "Facebook 411.1",
  "Facebook 412.0",
  "Facebook 413.0",
  "Facebook 413.1",
  "Facebook 414.0",
  "Facebook 415.0",
  "Facebook 415.1",
  "Facebook 416.0",
  "Facebook 417.0",
  "Facebook 418.0",
  "Facebook 419.0",
  "Facebook 420.0",
  "Facebook 421.0",
  "Facebook 422.0",
  "Facebook 423.0",
  "Facebook 424.0",
  "Facebook 68.0",
  "Firefox Focus ",
  "Firefox Focus 7.0",
  "Firefox Mobile 100.0",
  "Firefox Mobile 101.0",
  "Firefox Mobile 102.0",
  "Firefox Mobile 103.0",
  "Firefox Mobile 103.0esrfirefox",
  "Firefox Mobile 103.0firefox",
  "Firefox Mobile 103.0gzip",
  "Firefox Mobile 103.1firefox",
  "Firefox Mobile 103.2firefox",
  "Firefox Mobile 104.0",
  "Firefox Mobile 105.0",
  "Firefox Mobile 106.0",
  "Firefox Mobile 107.0",
  "Firefox Mobile 108.0",
  "Firefox Mobile 109.0",
  "Firefox Mobile 110.0",
  "Firefox Mobile 111.0",
  "Firefox Mobile 112.0",
  "Firefox Mobile 113.0",
  "Firefox Mobile 114.0",
  "Firefox Mobile 115.0",
  "Firefox Mobile 116.0",
  "Firefox Mobile 117.0",
  "Firefox Mobile 118.0",
  "Firefox Mobile 119.0",
  "Firefox Mobile 120.0",
  "Firefox Mobile 121.0",
  "Firefox Mobile 122.0",
  "Firefox Mobile 123.0",
  "Firefox Mobile 48.0",
  "Firefox Mobile 65.0",
  "Firefox Mobile 67.0",
  "Firefox Mobile 68.0",
  "Firefox Mobile 68.6",
  "Firefox Mobile 69.0",
  "Firefox Mobile 70.0",
  "Firefox Mobile 71.0",
  "Firefox Mobile 72.0",
  "Firefox Mobile 73.0",
  "Firefox Mobile 74.0",
  "Firefox Mobile 75.0",
  "Firefox Mobile 76.0",
  "Firefox Mobile 77.0",
  "Firefox Mobile 78.0",
  "Firefox Mobile 79.0",
  "Firefox Mobile 79.01686340214271",
  "Firefox Mobile 80.0",
  "Firefox Mobile 81.0",
  "Firefox Mobile 82.0",
  "Firefox Mobile 83.0",
  "Firefox Mobile 84.0",
  "Firefox Mobile 85.0",
  "Firefox Mobile 86.0",
  "Firefox Mobile 87.0",
  "Firefox Mobile 88.0",
  "Firefox Mobile 89.0",
  "Firefox Mobile 91.0",
  "Firefox Mobile 92.0",
  "Firefox Mobile 93.0",
  "Firefox Mobile 94.0",
  "Firefox Mobile 95.0",
  "Firefox Mobile 96.0",
  "Firefox Mobile 97.0",
  "Firefox Mobile 98.0",
  "Firefox Mobile 99.0",
  "Firefox Mobile iOS 102.0",
  "Firefox Mobile iOS 102.1",
  "Firefox Mobile iOS 103.0",
  "Firefox Mobile iOS 103.1",
  "Firefox Mobile iOS 104.2",
  "Firefox Mobile iOS 105.0",
  "Firefox Mobile iOS 105",
  "Firefox Mobile iOS 106.0",
  "Firefox Mobile iOS 106.1",
  "Firefox Mobile iOS 106.2",
  "Firefox Mobile iOS 107.2",
  "Firefox Mobile iOS 107",
  "Firefox Mobile iOS 108.1",
  "Firefox Mobile iOS 108",
  "Firefox Mobile iOS 109.0",
  "Firefox Mobile iOS 109",
  "Firefox Mobile iOS 110.0",
  "Firefox Mobile iOS 110.1",
  "Firefox Mobile iOS 110.2",
  "Firefox Mobile iOS 110",
  "Firefox Mobile iOS 111.0",
  "Firefox Mobile iOS 111.1",
  "Firefox Mobile iOS 111.2",
  "Firefox Mobile iOS 112.0",
  "Firefox Mobile iOS 112.2",
  "Firefox Mobile iOS 112",
  "Firefox Mobile iOS 113.0",
  "Firefox Mobile iOS 113.1",
  "Firefox Mobile iOS 113.2",
  "Firefox Mobile iOS 113",
  "Firefox Mobile iOS 114.0",
  "Firefox Mobile iOS 114.1",
  "Firefox Mobile iOS 114.2",
  "Firefox Mobile iOS 114.3",
  "Firefox Mobile iOS 114.4",
  "Firefox Mobile iOS 114",
  "Firefox Mobile iOS 14.0",
  "Firefox Mobile iOS 15.0",
  "Firefox Mobile iOS 2.0",
  "Firefox Mobile iOS 32.0",
  "Firefox Mobile iOS 33.0",
  "Firefox Mobile iOS 33.1",
  "Firefox Mobile iOS 34.0",
  "Firefox Mobile iOS 34.2",
  "Firefox Mobile iOS 36.0",
  "Firefox Mobile iOS 38.1",
  "Firefox Mobile iOS 39.0",
  "Firefox Mobile iOS 4.0",
  "Firefox Mobile iOS 40.2",
  "Firefox Mobile iOS 5.0",
  "Firefox Mobile iOS 69.0",
  "Firefox Mobile iOS 7.5",
  "Firefox Mobile iOS 70.0",
  "Firefox Mobile iOS 71.0",
  "Firefox Mobile iOS 72.0",
  "Firefox Mobile iOS 73.0",
  "Firefox Mobile iOS 74.0",
  "Firefox Mobile iOS 75.0",
  "Firefox Mobile iOS 76.0",
  "Firefox Mobile iOS 77.0",
  "Firefox Mobile iOS 78.0",
  "Firefox Mobile iOS 79.0",
  "Firefox Mobile iOS 8.1",
  "Firefox Mobile iOS 80.0",
  "Firefox Mobile iOS 81.0",
  "Firefox Mobile iOS 82.0",
  "Firefox Mobile iOS 83.0",
  "Firefox Mobile iOS 96.0",
  "Firefox Mobile iOS 96",
  "Firefox Mobile iOS 97.0",
  "Firefox Mobile iOS 97",
  "Firefox Mobile iOS 98.0",
  "Firefox Mobile iOS 98.2",
  "Firefox Mobile iOS 98",
  "Firefox Mobile iOS 99.1",
  "Firefox Mobile iOS 99",
  "IE Mobile 10.0",
  "IE Mobile 7.11",
  "Line 13.8",
  "MIUI Browser 10.1",
  "MIUI Browser 10.4",
  "MIUI Browser 10.9",
  "MIUI Browser 11.9",
  "MIUI Browser 12.11",
  "MIUI Browser 12.15",
  "MIUI Browser 12.2",
  "MIUI Browser 12.24",
  "MIUI Browser 12.4",
  "MIUI Browser 12.8",
  "MIUI Browser 13.11",
  "MIUI Browser 13.14",
  "MIUI Browser 13.16",
  "MIUI Browser 13.18",
  "MIUI Browser 13.19",
  "MIUI Browser 13.21",
  "MIUI Browser 13.22",
  "MIUI Browser 13.23",
  "MIUI Browser 13.25",
  "MIUI Browser 13.27",
  "MIUI Browser 13.28",
  "MIUI Browser 13.29",
  "MIUI Browser 13.30",
  "MIUI Browser 13.31",
  "MIUI Browser 13.32",
  "MIUI Browser 13.4",
  "MIUI Browser 13.6",
  "MIUI Browser 16.9",
  "MIUI Browser 17.5",
  "MIUI Browser 17.6",
  "MIUI Browser 2.1",
  "MIUI Browser 8.5",
  "MIUI Browser 9.5",
  "Mobile Safari ",
  "Mobile Safari 10.0",
  "Mobile Safari 10.1",
  "Mobile Safari 10.2",
  "Mobile Safari 10.3",
  "Mobile Safari 10.4",
  "Mobile Safari 10.5",
  "Mobile Safari 10.6",
  "Mobile Safari 10.7",
  "Mobile Safari 103",
  "Mobile Safari 11.0",
  "Mobile Safari 11.1",
  "Mobile Safari 11.2",
  "Mobile Safari 11.3",
  "Mobile Safari 11.4",
  "Mobile Safari 11.5",
  "Mobile Safari 11.6",
  "Mobile Safari 11.7",
  "Mobile Safari 115",
  "Mobile Safari 12.0",
  "Mobile Safari 12.1",
  "Mobile Safari 12.2",
  "Mobile Safari 12.3",
  "Mobile Safari 12.4",
  "Mobile Safari 12.5",
  "Mobile Safari 12.6",
  "Mobile Safari 12.7",
  "Mobile Safari 13.0",
  "Mobile Safari 13.1",
  "Mobile Safari 13.2",
  "Mobile Safari 13.3",
  "Mobile Safari 13.4",
  "Mobile Safari 13.5",
  "Mobile Safari 13.6",
  "Mobile Safari 13.7",
  "Mobile Safari 14.0",
  "Mobile Safari 14.1",
  "Mobile Safari 14.2",
  "Mobile Safari 14.3",
  "Mobile Safari 14.4",
  "Mobile Safari 14.5",
  "Mobile Safari 14.6",
  "Mobile Safari 14.7",
  "Mobile Safari 14.8",
  "Mobile Safari 15.0",
  "Mobile Safari 15.1",
  "Mobile Safari 15.2",
  "Mobile Safari 15.3",
  "Mobile Safari 15.4",
  "Mobile Safari 15.5",
  "Mobile Safari 15.6",
  "Mobile Safari 15.7",
  "Mobile Safari 16.0",
  "Mobile Safari 16.1",
  "Mobile Safari 16.166",
  "Mobile Safari 16.2",
  "Mobile Safari 16.21",
  "Mobile Safari 16.3",
  "Mobile Safari 16.399",
  "Mobile Safari 16.4",
  "Mobile Safari 16.5",
  "Mobile Safari 16.6",
  "Mobile Safari 16",
  "Mobile Safari 17.0",
  "Mobile Safari 2.6",
  "Mobile Safari 3.0",
  "Mobile Safari 4.0",
  "Mobile Safari 5.1",
  "Mobile Safari 5.2",
  "Mobile Safari 537.36",
  "Mobile Safari 537",
  "Mobile Safari 6.0",
  "Mobile Safari 600.1",
  "Mobile Safari 601.1",
  "Mobile Safari 602.1",
  "Mobile Safari 604.1",
  "Mobile Safari 605.1",
  "Mobile Safari 7.0",
  "Mobile Safari 7534.48",
  "Mobile Safari 8.0",
  "Mobile Safari 8614.3",
  "Mobile Safari 8614.4",
  "Mobile Safari 8615.2",
  "Mobile Safari 9.0",
  "Mobile Safari 9.2",
  "Mobile Safari 9.3",
  "Mobile Safari 9537.53",
  "Mobile Safari 98",
  "Mobile Safari",
  "Mobile Silk 3.13",
  "Mobile Silk 3.2",
  "NetFront ",
  "Nokia Browser 8.5",
  "Opera Mini 4.0",
  "Opera Mini 4.0",
  "Opera Mobile 1.0",
  "Opera Mobile 10.5",
  "Opera Mobile 10.6",
  "Opera Mobile 10.8",
  "Opera Mobile 10.9",
  "Opera Mobile 11.0",
  "Opera Mobile 11.1",
  "Opera Mobile 12.00",
  "Opera Mobile 37.0",
  "Opera Mobile 44.12",
  "Opera Mobile 44.14",
  "Opera Mobile 44.6",
  "Opera Mobile 48.2",
  "Opera Mobile 58.2",
  "Opera Mobile 60.0",
  "Opera Mobile 60.3",
  "Opera Mobile 61.0",
  "Opera Mobile 61.2",
  "Opera Mobile 62.0",
  "Opera Mobile 62.1",
  "Opera Mobile 62.2",
  "Opera Mobile 62.3",
  "Opera Mobile 63.0",
  "Opera Mobile 63.3",
  "Opera Mobile 64.0",
  "Opera Mobile 64.1",
  "Opera Mobile 64.2",
  "Opera Mobile 65.2",
  "Opera Mobile 66.0",
  "Opera Mobile 66.1",
  "Opera Mobile 66.2",
  "Opera Mobile 66.4",
  "Opera Mobile 66.6",
  "Opera Mobile 67.0",
  "Opera Mobile 67.1",
  "Opera Mobile 68.0",
  "Opera Mobile 68.3",
  "Opera Mobile 69.0",
  "Opera Mobile 69.2",
  "Opera Mobile 69.3",
  "Opera Mobile 7.6",
  "Opera Mobile 70.0",
  "Opera Mobile 70.3",
  "Opera Mobile 71.3",
  "Opera Mobile 72.0",
  "Opera Mobile 72.2",
  "Opera Mobile 72.3",
  "Opera Mobile 72.4",
  "Opera Mobile 72.5",
  "Opera Mobile 73.0",
  "Opera Mobile 73.2",
  "Opera Mobile 73.3",
  "Opera Mobile 74.0",
  "Opera Mobile 74.1",
  "Opera Mobile 74.2",
  "Opera Mobile 74.3",
  "Opera Mobile 75.0",
  "Opera Mobile 75.1",
  "Opera Mobile 75.2",
  "Opera Mobile 75.3",
  "Opera Mobile 75.4",
  "Opera Mobile 76.0",
  "Opera Mobile 76.1",
  "Opera Mobile 76.2",
  "Opera Mobile 77.0",
  "Opera Mobile 8.6",
  "Opera Mobile 9.1",
  "Opera Mobile 9.2",
  "Opera Mobile 92.0",
  "Opera Mobile N/A",
  "Pinterest ",
  "Pinterest",
  "Puffin 4.7",
  "Puffin 5.1",
  "Puffin 5.2",
  "Puffin 9.10",
  "Puffin 9.9",
  "Safari 10.0",
  "Safari 11.0",
  "Safari 11.2",
  "Safari 11.4",
  "Safari 12.0",
  "Safari 12.1",
  "Safari 12.3",
  "Safari 12.5",
  "Safari 13.7",
  "Safari 14.6",
  "Safari 15.5",
  "Safari 16.0",
  "Safari 9.1",
  "Samsung Browser ",
  "Samsung Browser 1.0",
  "Samsung Browser 1.1",
  "Samsung Browser 10.2",
  "Samsung Browser 11.0",
  "Samsung Browser 11.1",
  "Samsung Browser 11.2",
  "Samsung Browser 12.0",
  "Samsung Browser 12.1",
  "Samsung Browser 13.0",
  "Samsung Browser 13.2",
  "Samsung Browser 14.0",
  "Samsung Browser 14.2",
  "Samsung Browser 15.0",
  "Samsung Browser 16.0",
  "Samsung Browser 16.2",
  "Samsung Browser 17.0",
  "Samsung Browser 18.0",
  "Samsung Browser 19.0",
  "Samsung Browser 2.0",
  "Samsung Browser 2.1",
  "Samsung Browser 2.2",
  "Samsung Browser 20.0",
  "Samsung Browser 21.0",
  "Samsung Browser 21.1",
  "Samsung Browser 22.0",
  "Samsung Browser 3.0",
  "Samsung Browser 3.4",
  "Samsung Browser 3.5",
  "Samsung Browser 4.0",
  "Samsung Browser 4.2",
  "Samsung Browser 5.0",
  "Samsung Browser 5.2",
  "Samsung Browser 6.0",
  "Samsung Browser 6.2",
  "Samsung Browser 6.4",
  "Samsung Browser 7.0",
  "Samsung Browser 7.2",
  "Samsung Browser 7.4",
  "Samsung Browser 8.0",
  "Samsung Browser 8.2",
  "Samsung Browser 9.0",
  "Samsung Browser 9.2",
  "Samsung Browser 9.4",
  "UC Browser 10.10",
  "UC Browser 12.10",
  "UC Browser 12.12",
  "UC Browser 12.13",
  "UC Browser 14.0",
  "UC Browser 8.8",
  "Vivaldi 2.9",
  "WeChat 7.0",
  "WeChat 8.0",
  "WhatsApp 2.23",
  "WhatsApp 2",
];

exports.Array = MOBILE_BROWSERS;
