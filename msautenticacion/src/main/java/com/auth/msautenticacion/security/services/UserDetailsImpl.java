package com.auth.msautenticacion.security.services;

import com.auth.msautenticacion.models.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private Long id;
    private String username;
    private String email;
    private Long sucursalId; // 🏢 Campo agregado correctamente

    @JsonIgnore
    private String password;

    // Aquí guardaremos los roles convertidos en "Authorities" de Spring
    private Collection<? extends GrantedAuthority> authorities;

    // 🛠️ CONSTRUCTOR CORREGIDO: Ahora recibe 'Long sucursalId' de forma explícita
    public UserDetailsImpl(Long id, String username, String email, String password, Long sucursalId,
                           Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.sucursalId = sucursalId; // Asignación correcta desde el parámetro
        this.authorities = authorities;
    }

    public Long getSucursalId() { return sucursalId; }

    // 🛠️ MÉTODO BUILD CORREGIDO: Agregada la coma faltante y el mapeo limpio
    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                user.getSucursalId(), // ← Coma corregida aquí
                authorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Long getId() { return id; }
    public String getEmail() { return email; }

    @Override
    public String getPassword() { return password; }

    @Override
    public String getUsername() { return username; }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}