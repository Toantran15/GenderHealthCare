package com.example.genderhealthcare.repository;

import com.example.genderhealthcare.dtos.MonthlyCountDTO;
import com.example.genderhealthcare.entity.ConsultationAppointment;
import com.example.genderhealthcare.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ConsultationAppointmentRepository extends JpaRepository<ConsultationAppointment, Long> {
    List<ConsultationAppointment> findByConsultant(User consultant);

    List<ConsultationAppointment> findByCustomer_Id(Long customerId);

    @Query("SELECT new com.example.genderhealthcare.dtos.MonthlyCountDTO( " +
            "CONCAT(YEAR(c.appointmentDateTime), '-', " +
            "CASE WHEN MONTH(c.appointmentDateTime) < 10 THEN CONCAT('0', MONTH(c.appointmentDateTime)) ELSE CONCAT('', MONTH(c.appointmentDateTime)) END), " +
            "COUNT(c)) " +
            "FROM ConsultationAppointment c " +
            "GROUP BY YEAR(c.appointmentDateTime), MONTH(c.appointmentDateTime) " +
            "ORDER BY YEAR(c.appointmentDateTime), MONTH(c.appointmentDateTime)")
    List<MonthlyCountDTO> countConsultationByMonth();



}
