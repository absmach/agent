port module Main exposing (Config, Model, Msg(..), configDecoder, configEncoder, emptyConfig, expectJson, expectStatus, init, main, parseMaybe, subscriptions, update, view)

import Bootstrap.Button as Button
import Bootstrap.CDN as CDN
import Bootstrap.Card as Card
import Bootstrap.Card.Block as Block
import Bootstrap.Form as Form
import Bootstrap.Form.Input as Input
import Bootstrap.Form.Select as Select
import Bootstrap.Grid as Grid
import Bootstrap.Grid.Col as Col
import Bootstrap.Grid.Row as Row
import Bootstrap.Utilities.Spacing as Spacing
import Browser
import Browser.Navigation as Nav
import Helpers exposing (faIcons, fontAwesome, parse)
import Html exposing (..)
import Html.Attributes exposing (..)
import Html.Events exposing (onClick)
import Http
import Json.Decode as D
import Json.Encode as E
import File
import File.Select
import Task
import Url
import Url.Builder as B


-- PORTS


port fileToBase64 : String -> Cmd msg


port base64Result : (String -> msg) -> Sub msg


agentBase : String
agentBase =
    "http://localhost:9999"


main : Program () Model Msg
main =
    Browser.application
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , onUrlChange = UrlChanged
        , onUrlRequest = LinkClicked
        }


type alias Config =
    { httpPort : String
    , clientID : String
    , clientKey : String
    , channelID : String
    , logLevel : String
    , mqttURL : String
    , nodeRedURL : String
    , brokerURL : String
    }


emptyConfig : Config
emptyConfig =
    Config "" "" "" "" "info" "" "" ""


type alias NodeRedState =
    { flows : String
    , selectedFileName : String
    , response : String
    , loading : Bool
    }


type alias Model =
    { key : Nav.Key
    , config : Config
    , gotConfig : Bool
    , configResponse : String
    , nodeRed : NodeRedState
    , services : String
    , execCmd : String
    , execResponse : String
    }


type Msg
    = LinkClicked Browser.UrlRequest
    | UrlChanged Url.Url
      -- Config
    | GetConfig
    | GotConfig (Result Http.Error Config)
    | PostConfig
    | PostedConfig (Result Http.Error String)
    | SubmitPort String
    | SubmitClientID String
    | SubmitClientKey String
    | SubmitChannelID String
    | SubmitLogLevel String
    | SubmitMqttURL String
    | SubmitNodeRedURL String
    | SubmitBrokerURL String
      -- Node-RED
    | NodeRedPing
    | NodeRedFlows
    | NodeRedState_
    | NodeRedDeploy
    | NodeRedAddFlow
    | SelectFlowFile
    | FlowFileSelected File.File
    | FlowFileLoaded String
    | GotBase64 String
    | GotNodeRedResp (Result Http.Error String)
      -- Services
    | GetServices
    | GotServices (Result Http.Error String)
      -- Exec
    | SubmitExecCmd String
    | RunExec
    | GotExecResp (Result Http.Error String)


init : () -> Url.Url -> Nav.Key -> ( Model, Cmd Msg )
init _ url key =
    ( { key = key
      , config = emptyConfig
      , gotConfig = False
      , configResponse = ""
      , nodeRed = NodeRedState "" "" "" False
      , services = ""
      , execCmd = ""
      , execResponse = ""
      }
    , Http.get
        { url = agentBase ++ "/config"
        , expect = expectJson GotConfig configDecoder
        }
    )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    let
        config =
            model.config

        nr =
            model.nodeRed
    in
    case msg of
        LinkClicked urlRequest ->
            case urlRequest of
                Browser.Internal url ->
                    ( model, Nav.pushUrl model.key (Url.toString url) )

                Browser.External _ ->
                    ( model, Cmd.none )

        UrlChanged _ ->
            ( model, Cmd.none )

        -- Config
        GetConfig ->
            ( model
            , Http.get
                { url = agentBase ++ "/config"
                , expect = expectJson GotConfig configDecoder
                }
            )

        GotConfig result ->
            case result of
                Ok cfg ->
                    ( { model | config = cfg, gotConfig = True, configResponse = "OK" }, Cmd.none )

                Err err ->
                    ( { model | configResponse = httpErrToString err }, Cmd.none )

        PostConfig ->
            ( model
            , Http.post
                { url = agentBase ++ "/config"
                , body = Http.jsonBody (configEncoder model.config)
                , expect = expectStatus PostedConfig
                }
            )

        PostedConfig result ->
            case result of
                Ok status ->
                    ( { model | configResponse = status }, Cmd.none )

                Err err ->
                    ( { model | configResponse = httpErrToString err }, Cmd.none )

        SubmitPort v ->
            ( { model | config = { config | httpPort = v } }, Cmd.none )

        SubmitClientID v ->
            ( { model | config = { config | clientID = v } }, Cmd.none )

        SubmitClientKey v ->
            ( { model | config = { config | clientKey = v } }, Cmd.none )

        SubmitChannelID v ->
            ( { model | config = { config | channelID = v } }, Cmd.none )

        SubmitLogLevel v ->
            ( { model | config = { config | logLevel = v } }, Cmd.none )

        SubmitMqttURL v ->
            ( { model | config = { config | mqttURL = v } }, Cmd.none )

        SubmitNodeRedURL v ->
            ( { model | config = { config | nodeRedURL = v } }, Cmd.none )

        SubmitBrokerURL v ->
            ( { model | config = { config | brokerURL = v } }, Cmd.none )

        -- Node-RED
        NodeRedPing ->
            ( { model | nodeRed = { nr | loading = True } }
            , postNodeRed "nodered-ping" "" GotNodeRedResp
            )

        NodeRedFlows ->
            ( { model | nodeRed = { nr | loading = True } }
            , postNodeRed "nodered-flows" "" GotNodeRedResp
            )

        NodeRedState_ ->
            ( { model | nodeRed = { nr | loading = True } }
            , postNodeRed "nodered-state" "" GotNodeRedResp
            )

        NodeRedDeploy ->
            ( { model | nodeRed = { nr | loading = True } }
            , postNodeRed "nodered-deploy" nr.flows GotNodeRedResp
            )

        NodeRedAddFlow ->
            ( { model | nodeRed = { nr | loading = True } }
            , postNodeRed "nodered-add-flow" nr.flows GotNodeRedResp
            )

        SelectFlowFile ->
            ( model, File.Select.file [ "application/json" ] FlowFileSelected )

        FlowFileSelected file ->
            ( { model | nodeRed = { nr | selectedFileName = File.name file, loading = True } }
            , Task.perform FlowFileLoaded (File.toString file)
            )

        FlowFileLoaded content ->
            ( { model | nodeRed = { nr | loading = False } }
            , fileToBase64 content
            )

        GotBase64 encoded ->
            ( { model | nodeRed = { nr | flows = encoded } }, Cmd.none )

        GotNodeRedResp result ->
            case result of
                Ok resp ->
                    ( { model | nodeRed = { nr | response = resp, loading = False } }, Cmd.none )

                Err err ->
                    ( { model | nodeRed = { nr | response = httpErrToString err, loading = False } }, Cmd.none )

        -- Services
        GetServices ->
            ( model
            , Http.get
                { url = agentBase ++ "/services"
                , expect = Http.expectString GotServices
                }
            )

        GotServices result ->
            case result of
                Ok body ->
                    ( { model | services = body }, Cmd.none )

                Err err ->
                    ( { model | services = httpErrToString err }, Cmd.none )

        -- Exec
        SubmitExecCmd v ->
            ( { model | execCmd = v }, Cmd.none )

        RunExec ->
            ( model
            , Http.post
                { url = agentBase ++ "/exec"
                , body =
                    Http.jsonBody
                        (E.object
                            [ ( "bn", E.string "exec:" )
                            , ( "n", E.string "exec" )
                            , ( "vs", E.string model.execCmd )
                            ]
                        )
                , expect = Http.expectString GotExecResp
                }
            )

        GotExecResp result ->
            case result of
                Ok resp ->
                    ( { model | execResponse = resp }, Cmd.none )

                Err err ->
                    ( { model | execResponse = httpErrToString err }, Cmd.none )


postNodeRed : String -> String -> (Result Http.Error String -> Msg) -> Cmd Msg
postNodeRed cmd flows toMsg =
    Http.post
        { url = agentBase ++ "/nodered"
        , body =
            Http.jsonBody
                (E.object
                    [ ( "command", E.string cmd )
                    , ( "flows", E.string flows )
                    ]
                )
        , expect = Http.expectString toMsg
        }


parseMaybe : Maybe String -> String
parseMaybe ms =
    case ms of
        Just s ->
            s

        Nothing ->
            ""


httpErrToString : Http.Error -> String
httpErrToString err =
    case err of
        Http.BadUrl u ->
            "Bad URL: " ++ u

        Http.Timeout ->
            "Request timed out"

        Http.NetworkError ->
            "Network error"

        Http.BadStatus code ->
            "HTTP " ++ String.fromInt code

        Http.BadBody body ->
            "Bad response: " ++ body


subscriptions : Model -> Sub Msg
subscriptions _ =
    base64Result GotBase64


view : Model -> Browser.Document Msg
view model =
    { title = "Magistrala Agent"
    , body =
        [ Grid.container []
            [ CDN.stylesheet
            , fontAwesome
            , h2 [ style "margin" "20px 0" ] [ text "Magistrala Agent" ]
            , Grid.row [ ]
                [ Grid.col [ Col.md6 ]
                    [ configCard model ]
                , Grid.col [ Col.md6 ]
                    [ nodeRedCard model ]
                ]
            , Grid.row [ Row.attrs [ style "margin-top" "20px" ] ]
                [ Grid.col [ Col.md6 ]
                    [ servicesCard model ]
                , Grid.col [ Col.md6 ]
                    [ execCard model ]
                ]
            ]
        ]
    }


configCard : Model -> Html Msg
configCard model =
    Card.config []
        |> Card.headerH4 []
            [ i [ class faIcons.settings, style "margin-right" "8px" ] []
            , text "Configuration"
            ]
        |> Card.block []
            [ Block.custom
                (div []
                    [ formGroup model.gotConfig model.config.httpPort "httpPort" "HTTP Port" "Agent HTTP API port" SubmitPort
                    , formGroup model.gotConfig model.config.clientID "clientID" "Client ID" "Magistrala client ID (MQTT username)" SubmitClientID
                    , formGroup model.gotConfig model.config.clientKey "clientKey" "Client Key" "Magistrala client secret (MQTT password)" SubmitClientKey
                    , formGroup model.gotConfig model.config.channelID "channelID" "Channel ID" "Magistrala channel ID" SubmitChannelID
                    , formGroup model.gotConfig model.config.mqttURL "mqttURL" "MQTT URL" "Magistrala MQTT broker URL" SubmitMqttURL
                    , formGroup model.gotConfig model.config.nodeRedURL "nodeRedURL" "Node-RED URL" "Node-RED API URL" SubmitNodeRedURL
                    , formGroup model.gotConfig model.config.brokerURL "brokerURL" "Broker URL" "Internal FluxMQ AMQP broker URL" SubmitBrokerURL
                    , Form.group []
                        [ Form.label [ for "logLevel" ] [ text "Log Level" ]
                        , Select.select [ Select.id "logLevel", Select.onChange SubmitLogLevel ]
                            [ Select.item [ value "debug", selected (model.config.logLevel == "debug") ] [ text "debug" ]
                            , Select.item [ value "info", selected (model.config.logLevel == "info") ] [ text "info" ]
                            , Select.item [ value "warn", selected (model.config.logLevel == "warn") ] [ text "warn" ]
                            , Select.item [ value "error", selected (model.config.logLevel == "error") ] [ text "error" ]
                            ]
                        ]
                    , div [ style "margin-top" "10px" ]
                        [ Button.button [ Button.primary, Button.onClick GetConfig ] [ text "Get Config" ]
                        , Button.button [ Button.success, Button.attrs [ Spacing.ml2 ], Button.onClick PostConfig ] [ text "Save Config" ]
                        ]
                    , if model.configResponse /= "" then
                        div [ style "margin-top" "8px", style "color" "#666" ] [ text ("Response: " ++ model.configResponse) ]

                      else
                        text ""
                    ]
                )
            ]
        |> Card.view


nodeRedCard : Model -> Html Msg
nodeRedCard model =
    Card.config []
        |> Card.headerH4 []
            [ i [ class "fas fa-project-diagram", style "margin-right" "8px" ] []
            , text "Node-RED"
            ]
        |> Card.block []
            [ Block.custom
                (div []
                    [ div [ style "margin-bottom" "10px" ]
                        [ Button.button [ Button.outlineSecondary, Button.attrs [ Spacing.mr1 ], Button.onClick NodeRedPing ] [ text "Ping" ]
                        , Button.button [ Button.outlineSecondary, Button.attrs [ Spacing.mr1 ], Button.onClick NodeRedState_ ] [ text "State" ]
                        , Button.button [ Button.outlineSecondary, Button.onClick NodeRedFlows ] [ text "Get Flows" ]
                        ]
                    , div [ style "margin-bottom" "12px" ]
                        [ Button.button
                            [ Button.outlineSecondary, Button.attrs [ Spacing.mr2 ], Button.onClick SelectFlowFile ]
                            [ i [ class "fas fa-file-code", style "margin-right" "6px" ] []
                            , text "Select JSON File"
                            ]
                        , span
                            [ style "color"
                                (if model.nodeRed.selectedFileName /= "" then
                                    "#28a745"

                                 else
                                    "#999"
                                )
                            ]
                            [ text
                                (if model.nodeRed.selectedFileName /= "" then
                                    "\u{2713} " ++ model.nodeRed.selectedFileName

                                 else
                                    "No file selected"
                                )
                            ]
                        ]
                    , div [ style "margin-bottom" "10px" ]
                        [ Button.button
                            ([ Button.primary, Button.attrs [ Spacing.mr1 ], Button.onClick NodeRedDeploy ]
                                ++ (if model.nodeRed.flows == "" then [ Button.disabled True ] else [])
                            )
                            [ text "Deploy Flows" ]
                        , Button.button
                            ([ Button.success, Button.onClick NodeRedAddFlow ]
                                ++ (if model.nodeRed.flows == "" then [ Button.disabled True ] else [])
                            )
                            [ text "Add Flow" ]
                        ]
                    , if model.nodeRed.loading then
                        div [] [ text "Loading..." ]

                      else if model.nodeRed.response /= "" then
                        div []
                            [ Form.label [] [ text "Response:" ]
                            , pre
                                [ style "background" "#f8f9fa"
                                , style "padding" "8px"
                                , style "font-size" "12px"
                                , style "max-height" "150px"
                                , style "overflow-y" "auto"
                                ]
                                [ text model.nodeRed.response ]
                            ]

                      else
                        text ""
                    ]
                )
            ]
        |> Card.view


servicesCard : Model -> Html Msg
servicesCard model =
    Card.config []
        |> Card.headerH4 []
            [ i [ class "fas fa-heartbeat", style "margin-right" "8px" ] []
            , text "Services"
            ]
        |> Card.block []
            [ Block.custom
                (div []
                    [ Button.button [ Button.outlineSecondary, Button.onClick GetServices ] [ text "Refresh" ]
                    , if model.services /= "" then
                        pre
                            [ style "margin-top" "10px"
                            , style "background" "#f8f9fa"
                            , style "padding" "8px"
                            , style "font-size" "12px"
                            , style "max-height" "200px"
                            , style "overflow-y" "auto"
                            ]
                            [ text model.services ]

                      else
                        p [ style "margin-top" "10px", style "color" "#999" ] [ text "No services registered yet." ]
                    ]
                )
            ]
        |> Card.view


execCard : Model -> Html Msg
execCard model =
    Card.config []
        |> Card.headerH4 []
            [ i [ class "fas fa-terminal", style "margin-right" "8px" ] []
            , text "Execute Command"
            ]
        |> Card.block []
            [ Block.custom
                (div []
                    [ Form.group []
                        [ Form.label [] [ text "Command" ]
                        , Input.text
                            [ Input.id "execCmd"
                            , Input.onInput SubmitExecCmd
                            , Input.value model.execCmd
                            , Input.placeholder "e.g. ls,-la"
                            ]
                        , Form.help [] [ text "Comma-separated: command,arg1,arg2" ]
                        ]
                    , Button.button [ Button.danger, Button.onClick RunExec ] [ text "Run" ]
                    , if model.execResponse /= "" then
                        pre
                            [ style "margin-top" "10px"
                            , style "background" "#f8f9fa"
                            , style "padding" "8px"
                            , style "font-size" "12px"
                            , style "max-height" "200px"
                            , style "overflow-y" "auto"
                            ]
                            [ text model.execResponse ]

                      else
                        text ""
                    ]
                )
            ]
        |> Card.view


formGroup : Bool -> String -> String -> String -> String -> (String -> Msg) -> Html Msg
formGroup gotConfig val id_ name_ desc_ msg =
    Form.group []
        [ Form.label [ for id_ ] [ text name_ ]
        , if gotConfig then
            Input.text [ Input.id id_, Input.onInput msg, Input.value val ]

          else
            Input.text [ Input.id id_, Input.onInput msg ]
        , Form.help [] [ text desc_ ]
        ]


configEncoder : Config -> E.Value
configEncoder config =
    E.object
        [ ( "server", E.object [ ( "port", E.string config.httpPort ) ] )
        , ( "channels", E.object [ ( "id", E.string config.channelID ) ] )
        , ( "mqtt"
          , E.object
                [ ( "url", E.string config.mqttURL )
                , ( "username", E.string config.clientID )
                , ( "password", E.string config.clientKey )
                ]
          )
        , ( "nodered", E.object [ ( "url", E.string config.nodeRedURL ) ] )
        , ( "log", E.object [ ( "level", E.string config.logLevel ) ] )
        ]


configDecoder : D.Decoder Config
configDecoder =
    D.map8 Config
        (D.at [ "server", "port" ] D.string |> D.maybe |> D.map parseMaybe)
        (D.at [ "mqtt", "username" ] D.string |> D.maybe |> D.map parseMaybe)
        (D.at [ "mqtt", "password" ] D.string |> D.maybe |> D.map parseMaybe)
        (D.at [ "channels", "id" ] D.string |> D.maybe |> D.map parseMaybe)
        (D.at [ "log", "level" ] D.string |> D.maybe |> D.map parseMaybe)
        (D.at [ "mqtt", "url" ] D.string |> D.maybe |> D.map parseMaybe)
        (D.at [ "nodered", "url" ] D.string |> D.maybe |> D.map parseMaybe)
        (D.at [ "server", "broker_url" ] D.string |> D.maybe |> D.map parseMaybe)



-- EXPECT


expectStatus : (Result Http.Error String -> msg) -> Http.Expect msg
expectStatus toMsg =
    Http.expectStringResponse toMsg <|
        \resp ->
            case resp of
                Http.BadUrl_ u ->
                    Err (Http.BadUrl u)

                Http.Timeout_ ->
                    Err Http.Timeout

                Http.NetworkError_ ->
                    Err Http.NetworkError

                Http.BadStatus_ metadata _ ->
                    Err (Http.BadStatus metadata.statusCode)

                Http.GoodStatus_ metadata _ ->
                    Ok (String.fromInt metadata.statusCode)


expectJson : (Result Http.Error a -> msg) -> D.Decoder a -> Http.Expect msg
expectJson toMsg decoder =
    Http.expectStringResponse toMsg <|
        \resp ->
            case resp of
                Http.BadUrl_ u ->
                    Err (Http.BadUrl u)

                Http.Timeout_ ->
                    Err Http.Timeout

                Http.NetworkError_ ->
                    Err Http.NetworkError

                Http.BadStatus_ metadata _ ->
                    Err (Http.BadStatus metadata.statusCode)

                Http.GoodStatus_ _ body ->
                    case D.decodeString decoder body of
                        Ok value ->
                            Ok value

                        Err err ->
                            Err (Http.BadBody (D.errorToString err))
