package com.ikedi.security.repository;

import com.ikedi.security.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {   // <class, id>

    Optional<User> findByEmail(String email);

}
