const cloudflareAnalytics = document.createElement("script");
cloudflareAnalytics.type = "module";
cloudflareAnalytics.src = "https://static.cloudflareinsights.com/beacon.min.js";
cloudflareAnalytics.setAttribute("data-cf-beacon", '{"token":"e4d406a7bc7f46ea9fc26f9b0344f4cb"}');
document.head.appendChild(cloudflareAnalytics);
