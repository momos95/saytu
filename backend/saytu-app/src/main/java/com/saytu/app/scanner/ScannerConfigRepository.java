package com.saytu.app.scanner;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScannerConfigRepository extends JpaRepository<ScannerConfigEntity, String> {

    List<ScannerConfigEntity> findAllByOrderByScannerIdAsc();
}
