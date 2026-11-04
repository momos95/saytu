package com.africodeshield.app.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEventEntity, Long> {

    Page<AuditEventEntity> findByTargetTypeAndTargetIdOrderByOccurredAtDesc(String targetType, String targetId,
                                                                            Pageable pageable);
}
