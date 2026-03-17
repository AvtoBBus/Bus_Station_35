import { useEffect, useState } from "react";
import { Button, Card, Form, ListGroup, Toast, ToastContainer } from "react-bootstrap";
import "./App.css";

import MainImage from "../public/mainImage.jpg";

type MessageType = {
    UserName: string;
    Text: string;
    Date: string;
};

const userMessageInit = {
    UserName: "User_" + new Date().getTime(),
    Text: "",
    Date: "",
};

export const App = () => {
    const [messages, setMessages] = useState<MessageType[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [userComment, setUserComment] = useState<MessageType>(userMessageInit);

    const updateComment = (newText: string) => {
        const copy = JSON.parse(JSON.stringify(userComment)) as MessageType;
        copy.Text = newText;
        setUserComment(copy);
    };

    const fetchData = () => {
        fetch("http://localhost:8000/api/messages")
            .then((r) => r.json())
            .then((result) => setMessages(result));
    };

    const sendComment = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        const body = JSON.parse(JSON.stringify(userComment));
        delete body.Date;

        fetch("http://localhost:8000/api/create", {
            method: "POST",
            body: JSON.stringify(body),
            headers: { "content-type": "application/json" },
        })
            .then((response) => {
                if (response.status !== 204) {
                    response.text().then((t) => {
                        setError(JSON.parse(t)["detail"]);
                    });
                }
            })
            .finally(() => {
                setUserComment(userMessageInit);
                fetchData();
            });
    };

    useEffect(() => {
        fetchData();

        const inter = setInterval(() => fetchData(), 5000);

        return () => clearInterval(inter);
    }, []);

    return (
        <>
            {error && (
                <>
                    <ToastContainer className="error-container">
                        <Toast onClose={() => setError(null)}>
                            <Toast.Header className="error-container__header" closeButton>
                                Внимание
                            </Toast.Header>
                            <Toast.Body>
                                {error}
                                <br />
                                <br />
                                {"*сделаешь так ещё раз мы тебя забаним)"}
                            </Toast.Body>
                        </Toast>
                    </ToastContainer>
                </>
            )}

            <Card className="post">
                <Card.Img src={MainImage} className="post__image" variant="top" />
                <Card.Title className="post__title">Честный обзор топика с WB (я не доволен)</Card.Title>
                <Card.Body className="post__body">
                    ⭐☆☆☆☆
                    <br />
                    <br />
                    Декольте такое глубокое, что видно, что я ела на завтрак.
                    <br />
                    <br />
                    Продавцам вопрос: вы шьёте для людей или для жирафов, которые любят показывать, где у них
                    заканчивается шея?
                    <br />
                    <br />
                    Я, конечно, понимаю, что сейчас мода на всё откровенное, но это уже не декольте, это "здравствуйте,
                    я ваша тётя из Амстердама". Я надела этот топ, чтобы выйти в магазин за хлебом, а в итоге стояла у
                    подъезда 20 минут, потому что три мужика предложили подвезти, один спросил, не такси ли я, а бабушка
                    с третьего этажа перестала со мной здороваться и теперь крестится, когда видит в окно.
                    <br />
                    <br />
                    Самое смешное, что на фотографиях с маркетплейса это выглядело как милый летний топ с "интересным
                    вырезом". Интересным для кого? Для хирурга, которому теперь видно, где у меня находится селезёнка? Я
                    пошла в нём к подруге на день рождения — она думала, что я пришла перекрывать дыру в заборе своей
                    грудью.
                    <br />
                    <br />
                    Пы.сы. Ношу теперь как снуд. На шею намотала — и норм. Правда, дышит тяжело, зато все думают, что я
                    модная и у меня просто такой шарф-трансформер.
                </Card.Body>
            </Card>

            <Card className="comments">
                <Card.Header className="comments__title">Комментарии</Card.Header>
                <ListGroup className="comments__list">
                    {messages.map((message) => {
                        return (
                            <>
                                <ListGroup.Item>
                                    <Card>
                                        <Card.Header>{message.UserName}</Card.Header>
                                        <Card.Body>{message.Text}</Card.Body>
                                    </Card>
                                </ListGroup.Item>
                            </>
                        );
                    })}
                </ListGroup>
                <Card.Footer>
                    <Form onSubmit={(e) => sendComment(e)}>
                        <Form.Label>Напишите свой комментарий</Form.Label>
                        <Form.Control as="textarea" onChange={(e) => updateComment(e.target.value)} />
                        <Button type="submit" className="send-button">
                            Отправить
                        </Button>
                    </Form>
                </Card.Footer>
            </Card>
        </>
    );
};
