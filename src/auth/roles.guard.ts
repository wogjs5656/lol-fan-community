import { Role } from 'src/user/types/userRole.type';

import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class RolesGuard extends AuthGuard('jwt') implements CanActivate {
  constructor(private reflector: Reflector) {
    super();
  }

  // canActivate는 트루면 넌 허용이되는 친구야 flase면 넌 허용이 안되는 친구야
  // 로그인이 된 상황에서 구분하는것
  async canActivate(context: ExecutionContext) {
    const authenticated = await super.canActivate(context);
    if (!authenticated) {
      return false;
    }

    // 이 데코레이터는 롤스의 메타데이터에 롤스를 넣는다
    // @Roles(Role.Admin) -> [Role.Admin]d을 뜻함 리플렉터를 통해서 
    // 메타데이터를 탐색하고 롤스의 키값을 가져와서 if문 체크를한다
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.role === role);
  }
}