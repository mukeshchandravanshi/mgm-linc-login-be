package com.medgenome.linc.login.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
@Data // Generates getters, setters, toString, equals, and hashCode
@NoArgsConstructor
@AllArgsConstructor
@Builder // Enables the builder pattern for object creation
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @NotBlank(message = "First name is required")
    private String firstName;

    @NotBlank(message = "Last name is required")
    private String lastName;

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;

    @Pattern(
            regexp = "^\\+?[0-9\\-\\s]{7,15}$",
            message = "Invalid phone number format"
    )
    @NotBlank(message = "Phone number is required")
    private String phoneNum;

    @Enumerated(EnumType.STRING)
    private Role role;

    @NotBlank(message = "Country is required")
    private String country;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters long")
    private String password;

    @NotBlank(message = "Account name is required")
    private String accountName;

    @Enumerated(EnumType.STRING)
    private Status status;

    @Column(updatable = false)
    private LocalDateTime createdDt;

    private LocalDateTime updatedDt;

    // Initialize createdDt on persist and updatedDt on update
    @PrePersist
    protected void onCreate() {
        this.createdDt = LocalDateTime.now();
        this.updatedDt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedDt = LocalDateTime.now();
    }

    // Spring Security methods
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "ROLE_" + role.name());
    }

    @Override
    public String getUsername() {
        return email != null ? email : phoneNum;
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
