package org.example.goodjobbackend.service;

import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.UserRole;
import org.example.goodjobbackend.repository.UserRepository;
import org.example.goodjobbackend.repository.EmployerRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;
import java.util.Collections;
import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class    OAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final EmployerRepository employerRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oauth2User);
        } catch (Exception ex) {
            OAuth2Error oauth2Error = new OAuth2Error("user_processing_error", "Failed to process OAuth2 user", null);
            throw new OAuth2AuthenticationException(oauth2Error, ex);
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oauth2User) {
        Map<String, Object> attributes = oauth2User.getAttributes();

        // Extract provider details
        String provider = userRequest.getClientRegistration().getRegistrationId();
        String providerId = extractAttribute(attributes, "sub");
        String email = extractAttribute(attributes, "email");
        String name = extractAttribute(attributes, "name");
        String avatarUrl = attributes.get("picture") != null ?
                extractAttribute(attributes, "picture") : null;

        // Validate required fields
        if (email == null || email.isEmpty()) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        // Find or create user
        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            updateExistingUser(user, name, avatarUrl, provider, providerId);
        } else {
            user = createNewUser(email, name, avatarUrl, provider, providerId);
        }

        // Kiểm tra xem user có phải là employer không
        boolean isEmployer = employerRepository.existsByUserId(user.getId());
        if (isEmployer && user.getRole() != UserRole.EMPLOYER) {
            user.setRole(UserRole.EMPLOYER);
            userRepository.save(user);
        }

        // Create a new OAuth2User with updated attributes
        Map<String, Object> updatedAttributes = new HashMap<>(attributes);
        updatedAttributes.put("user_id", user.getId());
        updatedAttributes.put("role", user.getRole().name());
        updatedAttributes.put("email", user.getEmail());
        updatedAttributes.put("name", user.getFullName());

        return new DefaultOAuth2User(
            Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())),
            updatedAttributes,
            "email"
        );
    }

    private String extractAttribute(Map<String, Object> attributes, String key) {
        Object value = attributes.get(key);
        return value != null ? String.valueOf(value) : null;
    }

    private void updateExistingUser(User user, String name, String avatarUrl,
                                    String provider, String providerId) {
        boolean needUpdate = false;

        if (name != null && !name.equals(user.getFullName())) {
            user.setFullName(name);
            needUpdate = true;
        }

        if (avatarUrl != null && !avatarUrl.equals(user.getAvatarUrl())) {
            user.setAvatarUrl(avatarUrl);
            needUpdate = true;
        }

        // Update provider details if they've changed
        if (!provider.equals(user.getProvider()) ||
                (providerId != null && !providerId.equals(user.getProviderId()))) {
            user.setProvider(provider);
            user.setProviderId(providerId);
            needUpdate = true;
        }

        // Set user as active when they log in
        if (!user.isEnabled()) {
            user.setEnabled(true);
            needUpdate = true;
        }

        if (needUpdate) {
            userRepository.save(user);
        }
    }

    private User createNewUser(String email, String name, String avatarUrl,
                               String provider, String providerId) {
        User newUser = new User();
        newUser.setEmail(email);
        newUser.setUsername(email); // Use email as username for OAuth2 users
        newUser.setFullName(name != null ? name : email);
        newUser.setAvatarUrl(avatarUrl);
        newUser.setProvider(provider);
        newUser.setProviderId(providerId);
        newUser.setRole(UserRole.USER); // Mặc định là USER
        newUser.setEnabled(true);

        return userRepository.save(newUser);
    }
}