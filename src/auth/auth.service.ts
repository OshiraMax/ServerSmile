import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
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

  async login(email: string, password: string): Promise<any> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (user && await bcrypt.compare(password, user.password)) {
      // Создаем JWT для пользователя
      const payload = { email: user.email, sub: user.id };
      return {
        access_token: this.jwtService.sign(payload),
      };
    }
    throw new Error('Email or password incorrect');
  }

  // Методы аутентификации...
}

