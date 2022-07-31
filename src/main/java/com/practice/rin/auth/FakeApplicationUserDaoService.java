package com.practice.rin.auth;

import com.google.common.collect.Lists;
import com.practice.rin.security.ApplicationUserPermissions;
import com.practice.rin.security.ApplicationUserRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.practice.rin.security.ApplicationUserRoles.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream().
                filter(user-> username.equals(user.getUsername()))
                .findFirst();
    }


    public List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        "Rin",
                        passwordEncoder.encode("pass1"),
                        SE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                        ),
                new ApplicationUser(
                        "Linda",
                        passwordEncoder.encode("pass2"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "Rio",
                        passwordEncoder.encode("pass3"),
                        SSE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );

        return applicationUsers;
    }
}
