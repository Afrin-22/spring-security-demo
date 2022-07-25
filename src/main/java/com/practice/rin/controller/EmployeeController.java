package com.practice.rin.controller;

import com.practice.rin.model.Employee;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/employee")
public class EmployeeController {

    private static final List<Employee> EMPLOYEES = Arrays.asList(
            new Employee(1, "Rin"),
            new Employee(2, "Rio"),
            new Employee(3, "Linda")
    );

    @GetMapping("{id}")
    public Employee getEmployee(@PathVariable("id") Integer employeeId) {
        return EMPLOYEES.stream()
                .filter(e -> employeeId.equals(e.getId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Employee " + employeeId + " does not exist."));
    }

}
