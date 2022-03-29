// ============================================= //
// Types for WebAssembly runtime                 //
//                                               //
// This file is generated. PLEASE DO NOT MODIFY. //
// ============================================= //

export type Body = ArrayBuffer;

export type ComplexAlias = ComplexGuestToHost;

export type ComplexGuestToHost = {
    simple: Simple;
    map: Record<string, Simple>;
};

/**
 * Multi-line doc comment with complex characters
 * & " , \ ! '
 */
export type ComplexHostToGuest = {
    list: Array<number>;
    points: Array<Point<number>>;
    recursive: Array<Point<Point<number>>>;
    complexNested?: Record<string, Array<FloatingPoint>>;

    /**
     * Raw identifiers are supported too.
     */
    type: string;
    value: Value;
} & Simple;

export type ExplicitedlyImportedType = {
    you_will_see_this: boolean;
};

export type FloatingPoint = Point<number>;

export type GroupImportedType1 = {
    you_will_see_this: boolean;
};

export type GroupImportedType2 = {
    you_will_see_this: boolean;
};

/**
 * Similar to the `RequestOptions` struct, but using types from the `http` crate.
 */
export type HttpRequestOptions = {
    url: string;
    method: Method;
    headers: Record<string, string>;
    body?: ArrayBuffer;
};

export type Method = 
    | "GET"
    | "POST"
    | "PUT"
    | "DELETE"
    | "HEAD"
    | "OPTIONS"
    | "CONNECT"
    | "PATCH"
    | "TRACE";

export type Point<T> = {
    Value: T;
};

/**
 * Represents an error with the request.
 */
export type RequestError =
    /**
     * Used when we know we don't have an active network connection.
     */
    | { type: "offline" }
    | { type: "no_route" }
    | { type: "connection_refused" }
    | { type: "timeout" }
    | {
        type: "server_error";

        /**
         * HTTP status code.
         */
        status_code: number;

        /**
         * Response body.
         */
        response: Body;
    }
    /**
     * Misc.
     */
    | { type: "other/misc"; reason: string };

export type RequestMethod =
    | "DELETE"
    | "GET"
    | "OPTIONS"
    | "POST"
    | "PUT";

export type RequestOptions = {
    url: string;
    method: RequestMethod;
    headers: Record<string, string>;
    body?: ArrayBuffer;
};

/**
 * A response to a request.
 */
export type Response = {
    /**
     * Response headers, by name.
     */
    headers: Record<string, string>;

    /**
     * Response body.
     */
    body: Body;
};

/**
 * A result that can be either successful (`Ok)` or represent an error (`Err`).
 */
export type Result<T, E> =
    /**
     * Represents a succesful result.
     */
    | { Ok: T }
    /**
     * Represents an error.
     */
    | { Err: E };

export type Simple = {
    foo: number;
    bar: string;
};

/**
 * Tagged dynamic value.
 */
export type Value =
    | { Integer: bigint }
    | { Float: number }
    | { List: Array<Value> }
    | { Map: Record<string, Value> };
