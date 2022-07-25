package com.practice.rin.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum ApplicationUserRoles {

    SE(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(
            ApplicationUserPermissions.CODE_COMMIT,
            ApplicationUserPermissions.CODE_DEPLOY,
            ApplicationUserPermissions.CODE_MERGE,
            ApplicationUserPermissions.CODE_PULL
    )),
    SSE(Sets.newHashSet(
            ApplicationUserPermissions.CODE_COMMIT,
            ApplicationUserPermissions.CODE_PULL
    ));

    private final Set<ApplicationUserPermissions> permissions;

    ApplicationUserRoles(Set<ApplicationUserPermissions> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermissions> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {

        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(p -> new SimpleGrantedAuthority(p.getPermission()))
                .collect(Collectors.toSet());

        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
