package tacos.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
@Autowired
    DataSource dataSource;
    @Autowired
    private UserDetailsService userDetailsService;
    @Bean
    public PasswordEncoder encoder() {
        return new StandardPasswordEncoder("53cr3t");

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth

                    .ldapAuthentication()

                    .userSearchBase("ou=people")
                    .userSearchFilter("(uid={0})")
                    .groupSearchBase("ou=groups")
                    .groupSearchFilter("member={0}")
                    .passwordCompare()
                    .passwordEncoder(new BCryptPasswordEncoder())
                    .passwordAttribute("passcode")
                    .contextSource()
                    .url("ldap://tacocloud.com:389/dc=tacocloud,dc=com")
                    .userDetailsService(userDetailsService)
                    .passwordEncoder(encoder());;
                    /**
                    .jdbcAuthentication()
                    .dataSource(dataSource)
                    .usersByUsernameQuery(
                            "select username, password, enabled from Users " +
                                    "where username=?")
                    .authoritiesByUsernameQuery(
                            "select username, authority from UserAuthorities " +
                                    "where username=?")
                    .passwordEncoder(new StandardPasswordEncoder("53cr3t"));
                     **/



        }
        @Override
        protected void configure(HttpSecurity http) throws Exception {
     .authorizeRequests()
                    .antMatchers("/design", "/orders")
                    .hasRole("ROLE_USER")
                    .antMatchers(“/”, "/**").permitAll()
     .and()
                    .formLogin()
                    .loginPage("/login");
        }
    }
}