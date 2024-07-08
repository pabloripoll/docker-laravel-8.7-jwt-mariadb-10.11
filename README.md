<div style="width:100%;float:left;clear:both;margin-bottom:50px;">
    <a href="https://github.com/pabloripoll?tab=repositories">
        <img style="width:150px;float:left;" src="https://pabloripoll.com/files/logo-light-100x300.png"/>
    </a>
</div>

# Blog Example Application - Backend Service

## Infrastructure

Aplication

- Alpine: 3.20
- Nginx: 1.26.1
- PHP version: 8.3.8
- PHP Framework: Laravel 11.11.1

Database

- Alpine: 3.20
- MariaDB: 10.11.6

## Frontend Projects

This repository is a complement of the following applications

- BlogFront: []()

- BlogAdmin: []()

## Design



## Security

Every authenticated session is stored in database as a Based 64 string per session required to navigate according to the user level, even for microservices too, and it is a model decoupled from users accounts to be migrated into any type of database engine.

Each user level session could have a different life time improving for individual or global life time configuration even between same users level.
