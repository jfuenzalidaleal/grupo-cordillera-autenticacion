package com.auth.msautenticacion.controllers;

import com.auth.msautenticacion.dto.LoginRequest;
import com.auth.msautenticacion.dto.SignupRequest;
import com.auth.msautenticacion.dto.JwtResponse;
import com.auth.msautenticacion.models.Role;
import com.auth.msautenticacion.models.User;
import com.auth.msautenticacion.repositories.RoleRepository;
import com.auth.msautenticacion.repositories.UserRepository;
import com.auth.msautenticacion.security.jwt.JwtUtils;
import com.auth.msautenticacion.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        // Líneas de rastreo en consola
        System.out.println("====== REVISANDO ENTRADA DESDE REACT ======");
        System.out.println("USER ENVIADO: [" + loginRequest.getUsername() + "]");
        System.out.println("PASS ENVIADA: [" + loginRequest.getPassword() + "]");
        System.out.println("LONGITUD PASS: " + (loginRequest.getPassword() != null ? loginRequest.getPassword().length() : 0));
        System.out.println("===========================================");

        // 1. Autenticar al usuario con las credenciales que vienen de React
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        // 2. Guardar la autenticación en el contexto de Spring Security
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. Obtener los detalles e información del usuario autenticado desde la BD
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // 4. Generar el Token JWT firmando con el Claim sucursalId dinámico
        String jwt = jwtUtils.generateJwtToken(userDetails.getUsername(), roles, userDetails.getSucursalId());

        // 5. Construir el objeto de respuesta original
        JwtResponse response = new JwtResponse(
                jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
        );

        // 6. 🎯 FIX CRÍTICO: Inyectamos el ID de la sucursal en el JSON para que useAuth() en React pueda leerlo
        response.setSucursalId(userDetails.getSucursalId());

        // 7. Retornar la respuesta HTTP con el payload completo hacia el Frontend
        return ResponseEntity.ok(response);
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<?> listarUsuarios(Authentication authentication) {

        try {

            UserDetailsImpl userDetails =
                    (UserDetailsImpl) authentication.getPrincipal();

            Long sucursalId = userDetails.getSucursalId();

            boolean esAdmin = userDetails.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

            List<User> usuariosDB;

            if (esAdmin) {

                System.out.println("ADMIN detectado -> mostrando todos los usuarios");

                usuariosDB = userRepository.findAll();

            } else {

                System.out.println(
                        "Usuario de sucursal "
                                + sucursalId
                                + " -> mostrando solo su sucursal"
                );

                usuariosDB = userRepository.findBySucursalId(sucursalId);
            }

            List<Map<String, Object>> usuarios = usuariosDB.stream()
                    .map(user -> Map.<String, Object>of(
                            "id", user.getId(),
                            "username", user.getUsername(),
                            "email", user.getEmail(),
                            "sucursalId", user.getSucursalId() != null
                                    ? user.getSucursalId()
                                    : 0,
                            "roles", user.getRoles().stream()
                                    .map(Role::getName)
                                    .collect(Collectors.toList())
                    ))
                    .collect(Collectors.toList());

            return ResponseEntity.ok(usuarios);

        } catch (Exception e) {

            e.printStackTrace();

            return ResponseEntity.status(500).body(
                    Map.of(
                            "error",
                            "Error al listar usuarios: " + e.getMessage()
                    )
            );
        }
    }
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signUpRequest) {
        // 1. Validaciones previas para evitar duplicados en la BD
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body("Error: ¡El nombre de usuario ya está en uso!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body("Error: ¡El correo electrónico ya está en uso!");
        }

        // 2. Crear la cuenta del nuevo usuario
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(encoder.encode(signUpRequest.getPassword()));
        user.setSucursalId(signUpRequest.getSucursalId());

        // 3. Asignar los roles correspondientes
        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {

            Role userRole = roleRepository.findByName("ROLE_USUARIO")
                    .orElseThrow(() ->
                            new RuntimeException("ROLE_USUARIO no encontrado"));

            roles.add(userRole);

        } else {
            strRoles.forEach(role -> {

                switch (role.toLowerCase()) {

                    case "admin":
                        roles.add(
                                roleRepository.findByName("ROLE_ADMIN")
                                        .orElseThrow(() ->
                                                new RuntimeException("ROLE_ADMIN no encontrado"))
                        );
                        break;

                    case "gerente":
                        roles.add(
                                roleRepository.findByName("ROLE_GERENTE")
                                        .orElseThrow(() ->
                                                new RuntimeException("ROLE_GERENTE no encontrado"))
                        );
                        break;

                    case "usuario":
                        roles.add(
                                roleRepository.findByName("ROLE_USUARIO")
                                        .orElseThrow(() ->
                                                new RuntimeException("ROLE_USUARIO no encontrado"))
                        );
                        break;

                    default:
                        throw new RuntimeException(
                                "Rol inválido recibido: " + role
                        );
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok("¡Usuario registrado exitosamente!");
    }
}