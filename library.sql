/*
SQLyog Ultimate v13.1.1 (32 bit)
MySQL - 10.4.28-MariaDB : Database - library
*********************************************************************
*/

/*!40101 SET NAMES utf8 */;

/*!40101 SET SQL_MODE=''*/;

/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/`library` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci */;

USE `library`;

/*Table structure for table `author_tbl` */

DROP TABLE IF EXISTS `author_tbl`;

CREATE TABLE `author_tbl` (
  `collection_id` int(11) NOT NULL,
  `author_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`author_id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

/*Data for the table `author_tbl` */

/*Table structure for table `books_authors` */

DROP TABLE IF EXISTS `books_authors`;

CREATE TABLE `books_authors` (
  `collection_id` int(11) NOT NULL AUTO_INCREMENT,
  `book_id` int(11) NOT NULL,
  `author_id` int(11) NOT NULL,
  PRIMARY KEY (`book_id`,`author_id`),
  KEY `fk_author` (`author_id`),
  KEY `collection_id` (`collection_id`),
  CONSTRAINT `fk_author` FOREIGN KEY (`author_id`) REFERENCES `author_tbl` (`author_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_book` FOREIGN KEY (`book_id`) REFERENCES `books_tbl` (`book_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

/*Data for the table `books_authors` */

/*Table structure for table `books_tbl` */

DROP TABLE IF EXISTS `books_tbl`;

CREATE TABLE `books_tbl` (
  `book_id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `author_id` int(11) NOT NULL,
  PRIMARY KEY (`book_id`),
  KEY `authorid` (`author_id`),
  CONSTRAINT `books_tbl_ibfk_1` FOREIGN KEY (`author_id`) REFERENCES `author_tbl` (`author_id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

/*Data for the table `books_tbl` */

/*Table structure for table `tokens_tbl` */

DROP TABLE IF EXISTS `tokens_tbl`;

CREATE TABLE `tokens_tbl` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `token` varchar(255) NOT NULL,
  `user_id` int(11) NOT NULL,
  `status` enum('active','expired') DEFAULT 'active',
  `expiry` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `tokens_tbl_ibfk_1` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=260 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

/*Data for the table `tokens_tbl` */

/*Table structure for table `users_tbl` */

DROP TABLE IF EXISTS `users_tbl`;

CREATE TABLE `users_tbl` (
  `user_id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

/*Data for the table `users_tbl` */

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
