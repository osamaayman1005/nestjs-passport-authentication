import { Schema, Prop, SchemaFactory } from "@nestjs/mongoose";
import { SchemaType, SchemaTypes, Types } from "mongoose";

@Schema()
export class User {
    @Prop({ type: SchemaTypes.ObjectId, auto: true })
    _id: Types.ObjectId;

    @Prop({unique: true})
    email: string;

    @Prop()
    password:string

    @Prop()
    refreshToken?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
