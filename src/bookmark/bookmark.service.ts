import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  CreateBookmarkDto,
  EditBookmarkDto,
} from './dto';

@Injectable()
export class BookmarkService {
  constructor(
    private readonly prismaService: PrismaService,
  ) {}

  async createBookmark(
    userId: string,
    dto: CreateBookmarkDto,
  ) {
    const bookmark =
      await this.prismaService.bookmark.create({
        data: {
          ...dto,
          userId,
        },
      });

    return bookmark;
  }

  getBookmarks(userId: string) {
    return this.prismaService.bookmark.findMany({
      where: {
        userId,
      },
    });
  }

  getBookmarkById(
    userId: string,
    bookmarkId: string,
  ) {
    return this.prismaService.bookmark.findFirst({
      where: {
        userId,
        id: bookmarkId,
      },
    });
  }

  async editBookmarkById(
    userId: string,
    bookmarkId: string,
    dto: EditBookmarkDto,
  ) {
    const bookmark =
      await this.prismaService.bookmark.findUnique(
        {
          where: {
            id: bookmarkId,
          },
        },
      );

    if (!bookmark || bookmark.userId !== userId) {
      throw new ForbiddenException(
        'Access to resources denied',
      );
    }

    return this.prismaService.bookmark.update({
      where: {
        id: bookmarkId,
      },
      data: {
        ...dto,
      },
    });
  }

  async deleteBookmarkById(
    userId: string,
    bookmarkId: string,
  ) {
    const bookmark =
      await this.prismaService.bookmark.findUnique(
        {
          where: {
            id: bookmarkId,
          },
        },
      );

    if (!bookmark || bookmark.userId !== userId) {
      throw new ForbiddenException(
        'Access to resources denied',
      );
    }

    await this.prismaService.bookmark.delete({
      where: {
        id: bookmarkId,
      },
    });
  }
}
