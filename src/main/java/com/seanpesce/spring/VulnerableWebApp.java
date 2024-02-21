// Author: Sean Pesce
// 
package com.seanpesce.spring;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystems;
import java.util.Arrays;
import java.util.logging.Logger;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;


@RestController
@SpringBootApplication
public class VulnerableWebApp {
    static Logger logger = Logger.getLogger(VulnerableWebApp.class.getName());

    public static final String CVE_ID = "CVE-2024-22243";
    public static final String PATH_REDIRECT = "/redirect";
    public static final String PATH_HEALTH_CHECK = "/health-check";

    public static short PORT = 9999;

    // Trusted hosts for redirects
    public static final String[] TRUSTED_REDIRECT_HOSTS = new String[]{
        "127.0.0.1",
        "github.com",
        "google.com",
        "localhost",
        "seanpesce.com",
        "seanpesce.github.io",
        "wikipedia.org",
    };

    // Trusted hosts for back-end requests
    public static final String[] TRUSTED_INTERNAL_HOSTS = new String[]{
        "127.0.0.1",
        "localhost",
    };


    public static ModelAndView makeGenericResponse(HttpStatus status, String title, String msg) {
        ModelAndView modelAndView = new ModelAndView("generic");
        modelAndView.setStatus(status);
        modelAndView.addObject("titleMessage", title);
        modelAndView.addObject("bodyMessage", msg);
        return modelAndView;
    }


    public static ModelAndView makeResponse400(String msg) {
        return makeGenericResponse(HttpStatus.BAD_REQUEST, "Error 400 - Bad Request", msg);
    }


    public static ModelAndView makeResponse200(String msg) {
        return makeGenericResponse(HttpStatus.OK, "Success", msg);
    }


    public static String makeHtmlHeader() {
        StringBuilder sBuilder = new StringBuilder();
        sBuilder.append("<!DOCTYPE html>\n");
        sBuilder.append("<!-- Author: Sean Pesce -->\n");
        sBuilder.append("<html>\n");
        sBuilder.append("<head>\n");
        sBuilder.append("<meta charset=\"UTF-8\">\n");
        sBuilder.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        sBuilder.append("<link rel=\"shortcut icon\" href=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAABBVBMVEU/UbU/UbQ/UbY+ULI/ULM+T7BAUrc+ULM7TKg+T7E8Tq0/ULQ9T687Tao/Urc+ULQ6SqQ4SJ5CVLxCVb5DVr9CVL0dJlQoNHRBVLtEV8I8Taw/UrZEV8M6SqYkL2kfJ1gSFzQAAAAKDRwYHkMmMW01RJc6S6hDVsA8TasmMW4dJVMMDyEIChcuO4QJDBoAAQEBAQMEBgwcJFA6S6c0Q5UZIUkHCRMBAgQcJVEjLWUvPIYGBxAKDR0BAQIDBAk3R54OEicCAgUpNXY5SaM8Ta0cJE8FBg0TGTYVGzszQZExP4wXHkMZIUhAU7k9T7A2RpxDVsFBVLwuO4I4SKFBU7tBU7r///9e5KOYAAAAAWJLR0RWCg3piQAAAAd0SU1FB+cGHgwIFs0EkqsAAAC6SURBVBjTY2BAAEYmZhYkLhMrIxs7BxOSACcXNw8vHwM/OyNMRECQh5GdQUiYjZ2ZEaSSkZGRTUSUQUycU0KSQUqagZ1NRkpWTp5BQVFJWUVVTZpBXUNTS1tHgUFXT1HfwNDI2MTUTFHR3MKSgdnK2sZW0U7W3sFR0VHRyZnBRc3Vzd3DU0Lay9vDzEfGl4HRz8+fPSCQTTYogD3YjwHoBibpECZ2dgY2CWamUGmIi7jBJDsDIzcDWQAAiSYStruNAvgAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjMtMDYtMzBUMTI6MDg6MjIrMDA6MDDAnJm4AAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIzLTA2LTMwVDEyOjA4OjIyKzAwOjAwscEhBAAAACh0RVh0ZGF0ZTp0aW1lc3RhbXAAMjAyMy0wNi0zMFQxMjowODoyMiswMDowMObUANsAAAAASUVORK5CYII=\">\n");
        sBuilder.append("<title>Spring " + CVE_ID + " | Sean Pesce</title>\n");
        sBuilder.append("<style>\n");
        sBuilder.append("body { font: normal 16px Verdana, Arial, sans-serif; padding: 20px; }\n");
        sBuilder.append("</style>\n");
        sBuilder.append("</head>\n");
        return sBuilder.toString();
    }


    @GetMapping("/")
    public String homepage() {
        StringBuilder sBuilder = new StringBuilder();
        sBuilder.append(makeHtmlHeader());
        sBuilder.append("<body>\n");
        sBuilder.append("<h1>" + CVE_ID + "</h1>\n");
        sBuilder.append("<b>Author: Sean Pesce</b>\n");
        sBuilder.append("<br><br><br>\n");
        sBuilder.append("This web app demonstrates potentially-exploitable scenarios for " + CVE_ID + " in the Spring Framework:\n");
        sBuilder.append("<br>\n");
        sBuilder.append("<ul>\n");
        sBuilder.append("<li><a href=\"" + PATH_REDIRECT + "\">Open redirect</a></li>\n");
        sBuilder.append("<li><a href=\"" + PATH_HEALTH_CHECK + "\">Server-Side Request Forgery (SSRF)</a></li>\n");
        sBuilder.append("</ul>\n");
        sBuilder.append("</body>\n");
        sBuilder.append("</html>\n");
        return sBuilder.toString();
    }


    // Example: Open Redirect (CWE-601)
    //     Exploitable with a URL such as "https://google.com[@evil.com"
    //     To test this, simply navigate to http://127.0.0.1:${PORT}/redirect?url=https://google.com%5b@evil.com
    @GetMapping(PATH_REDIRECT)
    public ModelAndView openRedirect(@RequestParam(name="url", required=false) String url) {
        // Verify that the user provided a redirect URL
        if (url == null || url.isEmpty()) {
            return makeResponse400("Please provide a redirect URL with the \"url\" parameter");
        }

        // Check for a valid web URL
        if (!(url.startsWith("http://") || url.startsWith("https://"))) {
            return makeResponse400("Not a valid web URL - must start with \"http(s)://\"");
        }

        // Parse the host from the redirect URL
        String host = UriComponentsBuilder.fromHttpUrl(url).build().getHost();
        //String host = UriComponentsBuilder.fromUriString(url).build().getHost();  // Also vulnerable

        // Confirm that the redirect URL points to a trusted website
        if (Arrays.asList(TRUSTED_REDIRECT_HOSTS).contains(host)) {
            // Redirect to the specified URL
            ModelAndView modelAndView = new ModelAndView("redirect:" + url);
            return modelAndView;
        }
        
        // Redirect URL does not point to a trusted host
        return makeResponse400("Invalid redirect URL - \"" + host + "\" is not a trusted host name ");
    }


    // Example: Server-side Request Forgery (SSRF) (CWE-918)
    //     Exploitable with a URL such as "https://evil.com[@127.0.0.1"
    //     To test this, simply navigate to http://127.0.0.1:${PORT}/health-check?url=https://evil.com%5b@127.0.0.1
    @GetMapping(PATH_HEALTH_CHECK)
    public ModelAndView ssrf(@RequestParam(name="url", required=false) String url) {
        // Verify that the user provided a server URL
        if (url == null || url.isEmpty()) {
            return makeResponse400("Please provide a server URL with the \"url\" parameter");
        }
        logger.info("Performing health check for URL: \"" + url + "\"");

        // Check for a valid web URL
        if (!(url.startsWith("http://") || url.startsWith("https://"))) {
            return makeResponse400("Not a valid web URL - must start with \"http(s)://\"");
        }

        // Parse the host from the server URL
        String host = "";
        try {
            host = new URL(url).getHost();
        } catch (MalformedURLException err) {
            logger.warning("Error for URL: \"" + url + "\":\n    " + err);
            return makeResponse400("Health check failed:\n " + err);
        }
        
        HttpHeaders headers = new HttpHeaders();

        // Check whether the server URL points to a trusted internal host
        if (Arrays.asList(TRUSTED_INTERNAL_HOSTS).contains(host)) {
            // Add a secret authentication token header for trusted internal servers
            logger.info("Appending auth token for internal host: \"" + host + "\"");
            headers.add("X-Auth", "SECRET_TOKEN_VALUE");
        }

        // Send an HTTP GET request to see if the target server is "healthy"
        ResponseEntity<String> responseEntity = null;
        try {

            // RestTemplate/RestOperations implementation:
            RestOperations restTemplate = new RestTemplate();
            HttpEntity<?> requestEntity = new HttpEntity<Object>(headers);
            responseEntity = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);

            // // WebClient implementation:
            // WebClient webClient = WebClient.create();
            // responseEntity = webClient.get()
            //         .uri(url)
            //         .headers(httpHeaders -> httpHeaders.addAll(headers))
            //         .retrieve()
            //         .toEntity(String.class)
            //         .block();

            // // RestClient implementation:
            // RestClient restClient = RestClient.create();
            // responseEntity = restClient.get()
            //         .uri(url)
            //         .headers(httpHeaders -> httpHeaders.addAll(headers))
            //         .retrieve()
            //         .toEntity(String.class);

        } catch (Exception err) {
            // Throws HttpClientErrorException if an HTTP 4XX response is received
            logger.warning("Error for URL: \"" + url + "\":\n    " + err);
            return makeResponse400("Health check failed:\n " + err);
        }

        if (responseEntity != null) {
            return makeResponse200("Health check passed: " + responseEntity.getStatusCodeValue());
        }
        return makeResponse400("Health check failed.");
    }


    public static void main(String[] args) throws URISyntaxException {
        // Get JAR file path for help output
        String jarName = VulnerableWebApp.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
        jarName = jarName.substring(jarName.lastIndexOf(FileSystems.getDefault().getSeparator()) + 1);
        if (Arrays.stream(args).anyMatch(arg -> arg.equals("--help") || arg.equals("-h"))) {
            System.out.println("Usage: \n\n  java -jar " + jarName + " [port]\n\nDefault port: " + PORT);
            System.exit(0);
        }

        if (args.length > 0) {
            PORT = Short.parseShort(args[0]);
        }
        System.setProperty("server.port", Short.toString(PORT));

        // Start the vulnerable web application
        SpringApplication.run(VulnerableWebApp.class, args);
    }
}