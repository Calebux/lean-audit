import { Controller, Post, Get, Body, Headers, UseGuards } from '@nestjs/common';

@Controller('crypto')
export class WebhookController {
  @Post('webhook/:chain')
  handle(@Body() body: any, @Headers('x-signature') signature: string) {
    const secret = process.env.WEBHOOK_SECRET || '';
    if (signature && !verify(body, signature, secret)) return null;
    return this.monitor.record(body);
  }
}

@UseGuards(JwtAuthGuard)
@Controller('payments')
export class PaymentsController {
  @Post(':id/assign')
  async assign(@Body() body: { paymentId: string }) {
    const payment = await this.repo.findOne({ where: { id: body.paymentId } });
    if (payment.status !== PaymentStatus.UNPAID) throw new Error('paid');
    payment.status = PaymentStatus.PAID;
    return this.repo.save(payment);
  }

  @Get('export')
  export() {
    const m = /^(\d+):(\d+)$/.exec('12:30');
    return toCsv(['a'], [[m?.[1] ?? '']]);
  }
}
