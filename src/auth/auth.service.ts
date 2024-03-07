import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity'; // Путь к вашей сущности пользователя
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async register(email: string, password: string): Promise<User> {
    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 12);

    // Создание нового пользователя
    const newUser = this.userRepository.create({
      email,
      password: hashedPassword,
    });

    // Сохранение пользователя в базе данных
    await this.userRepository.save(newUser);
    
    return newUser;
  }

  // Методы аутентификации...
}

