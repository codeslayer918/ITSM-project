package lt.vilniustech.itsm.mtls.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import lt.vilniustech.itsm.mtls.config.AppProperties;

/**
 * E-mail notifications (Mailpit in the lab). Sending is asynchronous: the response time of
 * the recovery endpoints must not reveal whether an e-mail was sent (account enumeration).
 */
@Service
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    private final JavaMailSender mailSender;
    private final String from;

    public NotificationService(JavaMailSender mailSender, AppProperties props) {
        this.mailSender = mailSender;
        this.from = props.mailFrom();
    }

    @Async
    public void send(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("[ITSM mTLS] " + subject);
        message.setText(body + "\n\nIf this was not you, contact the administrator immediately.\n");
        try {
            mailSender.send(message);
        } catch (MailException e) {
            log.warn("Could not send notification '{}': {}", subject, e.getMessage());
        }
    }
}
