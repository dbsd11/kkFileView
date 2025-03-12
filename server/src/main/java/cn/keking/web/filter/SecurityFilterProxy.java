package cn.keking.web.filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import cn.keking.service.cache.CacheService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.InitializingBean;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;

@Configuration
public class SecurityFilterProxy extends OncePerRequestFilter implements InitializingBean  {

    private final Logger logger = LoggerFactory.getLogger(SecurityFilterProxy.class);

    // 令牌自定义标识
    @Value("${token.header}")
    private String header;

    // 令牌秘钥
    @Value("${token.secret}")
    private String secret;

    // 令牌有效期（默认30分钟）
    @Value("${token.expireTime}")
    private int expireTime;

    @Autowired(required = false)
    private Config config;

    private String NOT_ALLOW_METHODS = "TRACE";

    private RedissonClient redissonClient;

    @Override
    public void afterPropertiesSet() throws ServletException {
        if(config != null) {
            this.redissonClient = Redisson.create(config);
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if((","+NOT_ALLOW_METHODS+",").indexOf(","+request.getMethod().toUpperCase()+",") > -1) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            response.setHeader("Content-Type", "text/html; charset=iso-8859-1");
            response.getWriter().println("Method Not Allowed");
            return;
        }

        String requestUri = request.getRequestURI();

        if(requestUri.isEmpty() || requestUri.equalsIgnoreCase("/") || requestUri.endsWith("index")) {
            String token = request.getParameter(header);
            if(token == null || token.isEmpty()) {
                throw new ServletException("no token provided ");
            }
            Claims claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();

            Cookie cookie = new Cookie(header, token);
            cookie.setPath("/");
            cookie.setMaxAge(-1);
            cookie.setHttpOnly(true);
            response.addCookie(cookie);
        }

        boolean needCheckLogin = requestUri.contains("onlinePreview") || requestUri.contains("picturesPreview") || requestUri.contains("getCorsFile") ||
            requestUri.contains("addTask") || requestUri.contains("fileUpload") || requestUri.contains("deleteFile") || requestUri.contains("listFiles") || requestUri.contains("directory");
            
        if(needCheckLogin) {
            String token = request.getHeader(header);
            if(token == null || token.isEmpty()) {
                token = request.getParameter("token");
                if(token == null || token.isEmpty()) {
                    Cookie[] cookies = request.getCookies();
                    if(cookies != null){
                        for(Cookie cookie : cookies){
                            if(cookie.getName().equalsIgnoreCase(header)){
                                token = cookie.getValue();
                            }
                        }
                    }
                }
            }

            if(token == null || token.isEmpty()) {
                throw new ServletException("no token in header ");
            }

            token = token.replace("Bearer ", "");

            Claims claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
            
            String userKey = "login_tokens:" + String.valueOf(claims.get("login_user_key"));
            if(redissonClient != null && !redissonClient.getBucket(userKey).isExists()) {
                throw new ServletException("token illegal");
            }
            logger.info("user {} access check {} success", claims.get("login_user_key"), requestUri);
        } else {
            logger.info("no need check access {}", requestUri);
        }

        super.doFilter(request, response, filterChain);
    }
}
