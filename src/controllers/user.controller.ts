// Uncomment these imports to begin using these cool features!

import {repository} from '@loopback/repository';
import {getJsonSchemaRef, post, requestBody} from '@loopback/rest';
import * as _ from 'lodash';
import {User} from '../models/user.model';
// import {inject} from '@loopback/context';
import {UserRepository} from '../repositories/user.repository';
import {validateCredentials} from '../services/validator';

export class UserController {
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,
  ) {}
  @post('/signup', {
    responses: {
      '200': {
        description: 'User',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async signUp(@requestBody() userData: User) {
    validateCredentials(_.pick(userData, ['email', 'password']));
    const savedUser = await this.userRepository.create(userData);
    delete savedUser.password;
    return savedUser;
  }
}
