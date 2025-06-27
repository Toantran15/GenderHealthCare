package com.example.genderhealthcare.controller;

import com.example.genderhealthcare.entity.STITest;
import com.example.genderhealthcare.entity.User;
import com.example.genderhealthcare.security.CustomUserDetails;
import com.example.genderhealthcare.service.STITestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@Controller
@RequestMapping("/sti")
public class STITestController {

    @Autowired
    private STITestService stiTestService;



    @PostMapping("/book")
    public String bookTest(@ModelAttribute STITest test) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        User customer = userDetails.getUser();

        test.setCustomer(customer);
        test.setBookingTime(LocalDateTime.now());
        test.setStatus("pending");

        stiTestService.bookTest(test);
        return "redirect:/my-tests";
    }



    // Dành cho Staff / Admin để xem và cập nhật kết quả


    @PostMapping("/update-result")
    public String updateTestResult(
            @RequestParam Long id,
            @RequestParam String result,
            @RequestParam @DateTimeFormat(pattern = "yyyy-MM-dd'T'HH:mm") LocalDateTime resultTime
    ) {
        stiTestService.updateResult(id, result, resultTime);
        return "redirect:/staff/all";
    }
}
