import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { CreateUserRequest } from './dto/create-user.request';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CurrentUser } from 'src/auth/current-user.decorator';
import { User } from './schema/users.schema';

@Controller('users')
export class UsersController {
    constructor(private readonly userService: UsersService) { }
    @Post()
    async createUser(
        @Body() request: CreateUserRequest
    ) {
        await this.userService.create(request);
    }
    @Get()
    @UseGuards(JwtAuthGuard)
    async getUsers(
        @CurrentUser() user: User
    ){
        console.log(user);
        return this.userService.getAllUsers();
    }
}