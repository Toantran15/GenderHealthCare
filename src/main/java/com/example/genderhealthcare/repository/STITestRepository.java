package com.example.genderhealthcare.repository;

import com.example.genderhealthcare.dtos.MonthlyCountDTO;
import com.example.genderhealthcare.entity.STITest;
import com.example.genderhealthcare.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface STITestRepository extends JpaRepository<STITest, Long> {
    List<STITest> findByCustomer(User customer);
    @Query("SELECT new com.example.genderhealthcare.dtos.MonthlyCountDTO( " +
            "CONCAT(YEAR(s.bookingTime), '-', " +
            "CASE WHEN MONTH(s.bookingTime) < 10 THEN CONCAT('0', MONTH(s.bookingTime)) ELSE CONCAT('', MONTH(s.bookingTime)) END), " +
            "COUNT(s)) " +
            "FROM STITest s " +
            "GROUP BY YEAR(s.bookingTime), MONTH(s.bookingTime) " +
            "ORDER BY YEAR(s.bookingTime), MONTH(s.bookingTime)")
    List<MonthlyCountDTO> countSTITestByMonth();


}
