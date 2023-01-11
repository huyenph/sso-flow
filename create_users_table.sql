CREATE TABLE Users (
    userID VARCHAR(100),
    username VARCHAR(50),
    password CHAR(60),
    email VARCHAR(20),
    role ENUM('Admin', 'Tier1', 'Tier2', 'Tier3')
);