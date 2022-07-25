package com.practice.rin.controller;

import com.practice.rin.model.Employee;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("manage/api/v1/employee")
@EnableGlobalMethodSecurity(prePostEnabled = true) //added to make @PreAuthorize effective
public class EmployeeManagementController {

    private static final List<Employee> EMPLOYEES = Arrays.asList(
            new Employee(1, "Rin"),
            new Employee(2, "Rio"),
            new Employee(3, "Linda")
    );

    //    hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_SSE')")
    public List<Employee> getAllEmployees() {
        System.out.println("GetAllEmployees");
        return EMPLOYEES;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('code:merge')")
    public void addEmployee(@RequestBody Employee employee) {
        System.out.println("Registered Employee: " + employee);
    }

    @PutMapping("{id}")
    @PreAuthorize("hasAuthority('code:merge')")
    public void UpdateEmployee(@PathVariable("id") Integer employeeId, @RequestBody Employee employee) {
        System.out.println("Updated Employee: " + String.format("%s- %s", employeeId, employee));
    }

    @DeleteMapping("{id}")
    @PreAuthorize("hasAnyAuthority('code:commit','code:pull')")
    public void deleteEmployee(@PathVariable("id") Integer employeeId) {
        System.out.println("Deleted Employee: " + employeeId);
    }
}
