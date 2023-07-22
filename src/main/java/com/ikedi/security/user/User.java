package com.ikedi.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data         // Equivalent to @Getter, @Setter, @RequiredArgsConstructor, @ToString, @EqualsAndHashCode.
@Builder      // design pattern builder
@NoArgsConstructor
@AllArgsConstructor
@Entity        // making the user class an entity
@Table(name = "_user")  // setting the table name
public class User implements UserDetails {    // user details help get your details from the database

    @Id
    @GeneratedValue
    private  Integer id;

    private String firstName;

    private String lastName;

    private String email;

    private String password;

    @Enumerated(EnumType.STRING)  // enum type is ordinal(0,1) or string (string value of enum)
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {   // Returns the authorities granted to the user. Cannot return null
        return List.of(new SimpleGrantedAuthority(role.name()));  // user can only have one role
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
