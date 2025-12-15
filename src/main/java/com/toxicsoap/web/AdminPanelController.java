package com.toxicsoap.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class AdminPanelController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/")
    public String index() {
        return "redirect:/admin";
    }

    @GetMapping("/admin")
    public String adminPanel(Model model) {
        // Get stats
        Integer productCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM products", Integer.class);
        Integer userCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
        Integer orderCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM orders", Integer.class);

        model.addAttribute("productCount", productCount);
        model.addAttribute("userCount", userCount);
        model.addAttribute("orderCount", orderCount);

        // Get recent data
        List<Map<String, Object>> products = jdbcTemplate.queryForList("SELECT * FROM products LIMIT 5");
        List<Map<String, Object>> users = jdbcTemplate.queryForList("SELECT id, username, email, role FROM users LIMIT 5");

        model.addAttribute("products", products);
        model.addAttribute("users", users);

        return "admin";
    }

    @PostMapping("/admin/reset")
    @ResponseBody
    public Map<String, Object> resetDatabase() {
        Map<String, Object> response = new HashMap<>();
        try {
            // Drop and recreate tables
            jdbcTemplate.execute("DROP TABLE IF EXISTS orders");
            jdbcTemplate.execute("DROP TABLE IF EXISTS products");
            jdbcTemplate.execute("DROP TABLE IF EXISTS users");

            // Recreate schema
            initializeDatabase();

            response.put("success", true);
            response.put("message", "Database reset successfully");
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "Reset failed: " + e.getMessage());
        }
        return response;
    }

    @GetMapping("/health")
    @ResponseBody
    public Map<String, Object> health() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "UP");
        status.put("service", "toxic-soap");
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            status.put("database", "UP");
        } catch (Exception e) {
            status.put("database", "DOWN");
        }
        return status;
    }

    private void initializeDatabase() {
        // Create products table
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255),
                description TEXT,
                price DECIMAL(10,2),
                category VARCHAR(100),
                image_url VARCHAR(500)
            )
        """);

        // Create users table
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(100) UNIQUE,
                password VARCHAR(255),
                email VARCHAR(255),
                role VARCHAR(50),
                api_token VARCHAR(255),
                credit_card VARCHAR(20),
                ssn VARCHAR(20)
            )
        """);

        // Create orders table
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT,
                product_id INT,
                quantity INT,
                total_price DECIMAL(10,2),
                status VARCHAR(50),
                order_date TIMESTAMP,
                shipping_address TEXT
            )
        """);

        // Insert sample data
        jdbcTemplate.execute("""
            INSERT INTO products (name, description, price, category, image_url) VALUES
            ('Laptop Pro', 'High-performance laptop', 1299.99, 'Electronics', 'http://example.com/laptop.jpg'),
            ('Wireless Mouse', 'Ergonomic wireless mouse', 49.99, 'Electronics', 'http://example.com/mouse.jpg'),
            ('Coffee Maker', 'Automatic coffee maker', 89.99, 'Kitchen', 'http://example.com/coffee.jpg'),
            ('Running Shoes', 'Professional running shoes', 129.99, 'Sports', 'http://example.com/shoes.jpg'),
            ('Desk Lamp', 'LED desk lamp', 39.99, 'Office', 'http://example.com/lamp.jpg')
        """);

        jdbcTemplate.execute("""
            INSERT INTO users (username, password, email, role, api_token, credit_card, ssn) VALUES
            ('user', 'user123', 'user@example.com', 'USER', 'tok_user_abc123', '4111-1111-1111-1111', '123-45-6789'),
            ('admin', 'admin123', 'admin@example.com', 'ADMIN', 'tok_admin_xyz789', '4222-2222-2222-2222', '987-65-4321'),
            ('guest', 'guest', 'guest@example.com', 'GUEST', 'tok_guest_temp', NULL, NULL)
        """);

        jdbcTemplate.execute("""
            INSERT INTO orders (user_id, product_id, quantity, total_price, status, order_date, shipping_address) VALUES
            (1, 1, 1, 1299.99, 'DELIVERED', '2024-01-15 10:30:00', '123 Main St, City, ST 12345'),
            (1, 2, 2, 99.98, 'SHIPPED', '2024-01-20 14:45:00', '123 Main St, City, ST 12345'),
            (2, 3, 1, 89.99, 'PENDING', '2024-01-25 09:15:00', '456 Admin Ave, Town, ST 67890'),
            (1, 4, 1, 129.99, 'PROCESSING', '2024-01-28 16:00:00', '123 Main St, City, ST 12345')
        """);
    }
}
