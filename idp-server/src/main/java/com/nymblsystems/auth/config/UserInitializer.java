package com.nymblsystems.auth.config;

import com.nymblsystems.auth.model.ClientUser;
import com.nymblsystems.auth.repository.UserRepository;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class UserInitializer {

    @Bean
    public ApplicationRunner usersInit(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            List<ClientUser> users = getUsers(passwordEncoder);
            for (ClientUser user : users) {
                if (!userRepository.existsByUsername(user.getUsername())) {
                    userRepository.save(user);
                }
            }
        };
    }

    private static List<ClientUser> getUsers(PasswordEncoder passwordEncoder) {
        List<ClientUser> users = new ArrayList<>();
        users.add(new ClientUser("admin", "jbennett@nymblsystems.com", passwordEncoder.encode("pass2word")));
        return users;
    }
}
