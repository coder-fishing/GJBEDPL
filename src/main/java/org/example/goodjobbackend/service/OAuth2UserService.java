package org.example.goodjobbackend.service;

import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.UserRole;
import org.example.goodjobbackend.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = oauth2User.getAttributes();

        String provider = userRequest.getClientRegistration().getRegistrationId();
        String providerId = String.valueOf(attributes.get("sub")); // Convert to String safely
        String email = String.valueOf(attributes.get("email"));
        String name = String.valueOf(attributes.get("name"));
        String avatarUrl = attributes.get("picture") != null ? String.valueOf(attributes.get("picture")) : null;

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setUsername(email); // Use email as username for OAuth2 users
                    newUser.setFullName(name);
                    newUser.setAvatarUrl(avatarUrl);
                    newUser.setProvider(provider);
                    newUser.setProviderId(providerId);
                    newUser.setRole(UserRole.USER);
                    newUser.setEnabled(true);
                    return userRepository.save(newUser);
                });

        // Cập nhật thông tin nếu có thay đổi
        boolean needUpdate = false;
        if (!name.equals(user.getFullName())) {
            user.setFullName(name);
            needUpdate = true;
        }
        if (avatarUrl != null && !avatarUrl.equals(user.getAvatarUrl())) {
            user.setAvatarUrl(avatarUrl);
            needUpdate = true;
        }
        if (needUpdate) {
            userRepository.save(user);
        }

        return oauth2User;
    }
}