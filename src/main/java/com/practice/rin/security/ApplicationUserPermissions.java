package com.practice.rin.security;

public enum ApplicationUserPermissions {

    CODE_COMMIT("code:commit"),
    CODE_PULL("code:pull"),
    CODE_MERGE("code:merge"),
    CODE_DEPLOY("code:deploy");

    private final String permission;

    ApplicationUserPermissions(String permissions) {
        this.permission = permissions;
    }

    public String getPermission() {
        return permission;
    }
}
