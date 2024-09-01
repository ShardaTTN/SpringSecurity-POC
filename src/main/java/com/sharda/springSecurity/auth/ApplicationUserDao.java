package com.sharda.springSecurity.auth;

import java.util.Optional;

public interface ApplicationUserDao {
    Optional<ApplicationUser> selectUserByUserName(String userName);
}
