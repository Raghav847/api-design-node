import app from "./server.ts";
import env from "../env.ts";

app.listen(env.PORT, () => {
    console.log(`server running on port: ${env.PORT}`)
})