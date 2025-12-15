-- Toxic SOAP - Database Initialization Script

-- Create products table
CREATE TABLE IF NOT EXISTS products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(100),
    image_url VARCHAR(500)
);

-- Create users table with sensitive data columns (for vuln testing)
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE,
    password VARCHAR(255),
    email VARCHAR(255),
    role VARCHAR(50),
    api_token VARCHAR(255),
    credit_card VARCHAR(20),
    ssn VARCHAR(20)
);

-- Create orders table
CREATE TABLE IF NOT EXISTS orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    product_id INT,
    quantity INT,
    total_price DECIMAL(10,2),
    status VARCHAR(50),
    order_date TIMESTAMP,
    shipping_address TEXT
);

-- Insert sample products (IGNORE duplicates on restart)
INSERT IGNORE INTO products (name, description, price, category, image_url) VALUES
('Laptop Pro 15', 'High-performance laptop with 16GB RAM and 512GB SSD', 1299.99, 'Electronics', 'http://example.com/images/laptop.jpg'),
('Wireless Mouse', 'Ergonomic wireless mouse with 6 buttons', 49.99, 'Electronics', 'http://example.com/images/mouse.jpg'),
('Mechanical Keyboard', 'RGB mechanical keyboard with Cherry MX switches', 149.99, 'Electronics', 'http://example.com/images/keyboard.jpg'),
('Coffee Maker Deluxe', '12-cup automatic coffee maker with timer', 89.99, 'Kitchen', 'http://example.com/images/coffee.jpg'),
('Running Shoes Pro', 'Professional running shoes with air cushioning', 129.99, 'Sports', 'http://example.com/images/shoes.jpg'),
('Desk Lamp LED', 'Adjustable LED desk lamp with 3 brightness levels', 39.99, 'Office', 'http://example.com/images/lamp.jpg'),
('Bluetooth Headphones', 'Noise-cancelling wireless headphones', 199.99, 'Electronics', 'http://example.com/images/headphones.jpg'),
('Water Bottle', 'Insulated stainless steel water bottle 32oz', 24.99, 'Sports', 'http://example.com/images/bottle.jpg'),
('Notebook Set', 'Pack of 5 premium notebooks', 19.99, 'Office', 'http://example.com/images/notebooks.jpg'),
('Smart Watch', 'Fitness tracker with heart rate monitor', 249.99, 'Electronics', 'http://example.com/images/watch.jpg');

-- Insert sample users with sensitive data (for vulnerability demonstration)
INSERT IGNORE INTO users (username, password, email, role, api_token, credit_card, ssn) VALUES
('user', 'user123', 'user@example.com', 'USER', 'tok_user_abc123xyz789', '4111-1111-1111-1111', '123-45-6789'),
('admin', 'admin123', 'admin@example.com', 'ADMIN', 'tok_admin_master_key_999', '4222-2222-2222-2222', '987-65-4321'),
('guest', 'guest', 'guest@example.com', 'GUEST', 'tok_guest_temporary', NULL, NULL),
('john.doe', 'password123', 'john.doe@company.com', 'USER', 'tok_john_secret_456', '4333-3333-3333-3333', '456-78-9012'),
('jane.smith', 'jane2024!', 'jane.smith@company.com', 'USER', 'tok_jane_private_789', '4444-4444-4444-4444', '789-01-2345');

-- Insert sample orders (IGNORE duplicates on restart)
INSERT IGNORE INTO orders (user_id, product_id, quantity, total_price, status, order_date, shipping_address) VALUES
(1, 1, 1, 1299.99, 'DELIVERED', '2024-01-15 10:30:00', '123 Main Street, Apt 4B, New York, NY 10001'),
(1, 2, 2, 99.98, 'SHIPPED', '2024-01-20 14:45:00', '123 Main Street, Apt 4B, New York, NY 10001'),
(2, 4, 1, 89.99, 'PENDING', '2024-01-25 09:15:00', '456 Admin Avenue, Suite 100, San Francisco, CA 94102'),
(1, 5, 1, 129.99, 'PROCESSING', '2024-01-28 16:00:00', '123 Main Street, Apt 4B, New York, NY 10001'),
(4, 3, 1, 149.99, 'DELIVERED', '2024-01-10 11:20:00', '789 Oak Lane, Chicago, IL 60601'),
(4, 7, 1, 199.99, 'SHIPPED', '2024-01-22 13:30:00', '789 Oak Lane, Chicago, IL 60601'),
(5, 10, 1, 249.99, 'PROCESSING', '2024-01-27 15:45:00', '321 Pine Road, Austin, TX 78701'),
(1, 6, 2, 79.98, 'CANCELLED', '2024-01-05 08:00:00', '123 Main Street, Apt 4B, New York, NY 10001'),
(2, 8, 3, 74.97, 'DELIVERED', '2024-01-12 10:00:00', '456 Admin Avenue, Suite 100, San Francisco, CA 94102'),
(5, 9, 5, 99.95, 'PENDING', '2024-01-29 09:30:00', '321 Pine Road, Austin, TX 78701');
