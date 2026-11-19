package com.haro.user.service;

import com.haro.user.entity.OutboxEvent;
import com.haro.user.event.EmailNotificationEvent;
import com.haro.user.repository.OutboxEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.UUID;

/**
 * Transactional outbox: events are written in the caller's transaction and published to Kafka by
 * {@link OutboxPollerService}.
 */
@Service
@RequiredArgsConstructor
public class OutboxService {

    public static final String EMAIL_TOPIC = "notification.email";
    public static final String USER_EVENTS_TOPIC = "user.events";
    public static final String AGGREGATE_USER = "USER";

    private final OutboxEventRepository outboxEventRepository;
    private final ObjectMapper objectMapper;

    /** Queues an email for the notification service. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void saveEvent(EmailNotificationEvent event) {
        saveEvent(EMAIL_TOPIC, AGGREGATE_USER, event.userId(), event.type(), event);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void saveEvent(String topic, String aggregateType, UUID aggregateId, String eventType, Object payload) {
        String json;
        try {
            json = objectMapper.writeValueAsString(payload);
        } catch (JacksonException e) {
            throw new IllegalStateException("Failed to serialize outbox event", e);
        }

        OutboxEvent outboxEvent = OutboxEvent.builder()
                .aggregateType(aggregateType)
                .aggregateId(aggregateId)
                .eventType(eventType)
                .topic(topic)
                .payload(json)
                .build();

        outboxEventRepository.save(outboxEvent);
    }
}
