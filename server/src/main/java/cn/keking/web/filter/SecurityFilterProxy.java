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
import org.springframework.beans.factory.InitializingBean;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;

@Configuration
public class SecurityFilterProxy extends OncePerRequestFilter implements InitializingBean  {

    // 令牌自定义标识
    @Value("${token.header}")
    private String header;

    // 令牌秘钥
    @Value("${token.secret}")
    private String secret;

    // 令牌有效期（默认30分钟）
    @Value("${token.expireTime}")
    private int expireTime;

    @Autowired
    private Config config;

    private String NOT_ALLOW_METHODS = "TRACE";

    private RedissonClient redissonClient;

    @Override
    public void afterPropertiesSet() throws ServletException {
        this.redissonClient = Redisson.create(config);
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

        String token = request.getHeader(header);
        if(token == null || token.isEmpty()) {
            token = request.getParameter("token");
            if(token == null || token.isEmpty()) {
                throw new ServletException("no token in header ");
            }
        }
        token = token.replace("Bearer ", "");

        Claims claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
        
        String userKey = "login_tokens:" + String.valueOf(claims.get("login_user_key"));
        if(!redissonClient.getBucket(userKey).isExists()) {
            throw new ServletException("token illegal");
        }

        super.doFilter(request, response, filterChain);
    }
}
